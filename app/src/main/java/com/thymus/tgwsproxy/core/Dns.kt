package com.thymus.tgwsproxy.core

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

/**
 * DNS with a small cache, IPv4 preference and a DNS-over-HTTPS rescue path.
 *
 * Two problems matter on mobile networks behind censorship:
 *  - the system resolver can be slow (it is called on a worker with a deadline), and
 *  - it can be poisoned: instead of NXDOMAIN it returns some unrelated IP, so the
 *    connection fails later and looks like a blocked server.
 *
 * Cloudflare front domains are always supposed to resolve into Cloudflare's own
 * ranges. If the system answer is outside them (or empty), the name is re-resolved
 * over DoH and the real address is used.
 */
object Dns {
    private const val TTL_MS = 10 * 60_000L
    private const val DOH_WINDOW_MS = 4000L

    private data class Entry(val addresses: List<InetAddress>, val at: Long)

    private val cache = ConcurrentHashMap<String, Entry>()
    private val executor = Executors.newCachedThreadPool { r ->
        Thread(r, "tgws-dns").apply { isDaemon = true }
    }

    /** `1.1.1.1` needs no DNS itself, so it is tried first. */
    private val dohEndpoints = listOf(
        "https://1.1.1.1/dns-query",
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
        "https://dns.quad9.net/dns-query",
    )

    private val IPV4_ANSWER = Regex("\"data\"\\s*:\\s*\"(\\d{1,3}(?:\\.\\d{1,3}){3})\"")

    /** Resolves [host] to addresses, IPv4 first. Never throws; returns an empty list. */
    fun resolve(host: String): List<InetAddress> {
        literalAddress(host)?.let { return listOf(it) }
        cached(host)?.let { return it }

        val system = systemLookup(host)
        if (system.isNotEmpty()) {
            cache[host] = Entry(system, System.currentTimeMillis())
            return system
        }
        return store(host, dohLookup(host))
    }

    /**
     * Resolution for Cloudflare-fronted names: trusts the system answer only when it
     * belongs to Cloudflare, otherwise asks DoH. As a last resort — DNS hijacked and
     * DoH blocked — the name is pointed at a Cloudflare edge IP, which serves any
     * proxied hostname by SNI.
     */
    fun resolveCf(host: String): List<InetAddress> {
        literalAddress(host)?.let { return listOf(it) }
        cached(host)?.let { return it }

        val system = systemLookup(host)
        if (system.isNotEmpty() && system.all { isCloudflare(it) }) {
            cache[host] = Entry(system, System.currentTimeMillis())
            return system
        }
        val doh = dohLookup(host)
        if (doh.isNotEmpty()) return store(host, doh)

        val edge = CF_EDGE_FALLBACK.mapNotNull {
            runCatching { InetAddress.getByName(it) }.getOrNull()
        }
        return store(host, (system + edge).distinct())
    }

    /** Opens a TCP connection to [host]:[port], trying every resolved address in turn. */
    fun connect(host: String, port: Int, timeoutMs: Int): Socket =
        connectTo(resolve(host), host, port, timeoutMs)

    fun connectTo(
        addresses: List<InetAddress>,
        host: String,
        port: Int,
        timeoutMs: Int,
    ): Socket {
        if (addresses.isEmpty()) throw java.net.UnknownHostException("$host: DNS lookup failed")
        var last: Throwable? = null
        for (address in addresses) {
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(address, port), timeoutMs)
                return socket
            } catch (t: Throwable) {
                last = t
                runCatching { socket.close() }
            }
        }
        throw last ?: java.net.ConnectException("$host:$port unreachable")
    }

    fun forget(host: String) {
        cache.remove(host)
    }

    private fun cached(host: String): List<InetAddress>? {
        val entry = cache[host] ?: return null
        if (System.currentTimeMillis() - entry.at < TTL_MS) return entry.addresses
        cache.remove(host)
        return null
    }

    private fun store(host: String, addresses: List<InetAddress>): List<InetAddress> {
        // Cache failures for a minute so a dead name does not stall every attempt.
        val ttlStart = if (addresses.isEmpty()) {
            System.currentTimeMillis() - TTL_MS + 60_000L
        } else {
            System.currentTimeMillis()
        }
        cache[host] = Entry(addresses, ttlStart)
        return addresses
    }

    private fun literalAddress(host: String): InetAddress? {
        val looksLikeIpv4 = host.count { it == '.' } == 3 &&
            host.all { it.isDigit() || it == '.' } &&
            host.split('.').all { it.isNotEmpty() && it.toIntOrNull() in 0..255 }
        val looksLikeIpv6 = host.contains(':')
        if (!looksLikeIpv4 && !looksLikeIpv6) return null
        return runCatching { InetAddress.getByName(host) }.getOrNull()
    }

    private fun systemLookup(host: String): List<InetAddress> {
        return try {
            val future = executor.submit<List<InetAddress>> { InetAddress.getAllByName(host).toList() }
            future.get(4000, TimeUnit.MILLISECONDS).preferIpv4()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    /** Queries all DoH endpoints at once and keeps the first non-empty answer. */
    private fun dohLookup(host: String): List<InetAddress> {
        val lock = Object()
        var result: List<InetAddress>? = null
        val latch = CountDownLatch(1)

        for (endpoint in dohEndpoints) {
            Thread({
                val answer = queryDoh(endpoint, host)
                if (answer.isEmpty()) return@Thread
                synchronized(lock) {
                    if (result == null) {
                        result = answer
                        latch.countDown()
                    }
                }
            }, "tgws-doh").apply {
                isDaemon = true
                start()
            }
        }

        latch.await(DOH_WINDOW_MS, TimeUnit.MILLISECONDS)
        return synchronized(lock) { result } ?: emptyList()
    }

    private fun queryDoh(endpoint: String, host: String): List<InetAddress> {
        return try {
            val url = URL("$endpoint?name=$host&type=A")
            val connection = url.openConnection() as HttpsURLConnection
            connection.connectTimeout = 3500
            connection.readTimeout = 3500
            connection.setRequestProperty("accept", "application/dns-json")
            connection.setRequestProperty("user-agent", "Thymus")
            val body = connection.inputStream.bufferedReader().use { it.readText() }
            connection.disconnect()
            IPV4_ANSWER.findAll(body)
                .mapNotNull { runCatching { InetAddress.getByName(it.groupValues[1]) }.getOrNull() }
                .distinct()
                .toList()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    fun List<InetAddress>.preferIpv4(): List<InetAddress> =
        sortedBy { if (it.address.size == 4) 0 else 1 }

    /**
     * Last-resort Cloudflare edge addresses. The edge terminates TLS for any zone it
     * proxies and routes by SNI/Host, so this works even when DNS is unusable.
     */
    private val CF_EDGE_FALLBACK = listOf("104.16.0.1")

    // Cloudflare's published IPv4 ranges, used to notice a hijacked DNS answer.
    private val CLOUDFLARE_RANGES = listOf(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ).map { cidr ->
        val (network, bits) = cidr.split('/')
        val address = ipv4ToLong(network)
        val mask = if (bits.toInt() == 0) 0L else (0xFFFFFFFFL shl (32 - bits.toInt())) and 0xFFFFFFFFL
        address to mask
    }

    fun isCloudflare(address: InetAddress): Boolean {
        val bytes = address.address
        if (bytes.size != 4) return false
        val value = ipv4ToLong(bytes)
        return CLOUDFLARE_RANGES.any { (network, mask) -> value and mask == network }
    }

    private fun ipv4ToLong(bytes: ByteArray): Long {
        var value = 0L
        for (byte in bytes) value = (value shl 8) or (byte.toLong() and 0xFF)
        return value
    }

    private fun ipv4ToLong(text: String): Long {
        var value = 0L
        for (part in text.split('.')) value = (value shl 8) or (part.toLong() and 0xFF)
        return value
    }
}
