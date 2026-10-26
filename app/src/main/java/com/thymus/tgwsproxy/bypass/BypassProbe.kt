package com.thymus.tgwsproxy.bypass

import android.util.Log
import com.thymus.tgwsproxy.core.TlsClientHello
import java.io.IOException
import java.io.InputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext

/** A TLS endpoint the configs are tried against. */
data class ProbeTarget(val host: String, val port: Int = 443)

/** One config's result against one target. */
data class ProbeOutcome(val ok: Boolean, val latencyMs: Long)

/** How one config did overall: [ok] of [total] targets answered, averaged latency. */
data class ProbeScore(
    val profile: BypassProfile,
    val ok: Int,
    val total: Int,
    val latencyMs: Long,
)

/**
 * Keeps probe sockets outside the VPN's own tunnel. [BypassService] installs this while
 * the tunnel is up, so a probe measures the candidate config instead of the running one.
 * The app is normally excluded from the tunnel, so this is only a safety net.
 */
object ProbeGuard {
    @Volatile
    var protect: ((Socket) -> Boolean)? = null
}

/**
 * Picks a working bypass config by doing what the tunnel does: send a TLS ClientHello
 * with the config's split applied and see whether the server answers with a ServerHello.
 *
 * A blocked handshake either resets or stays silent, so a reply is the same evidence the
 * real connection would get. Configs are tested in parallel; each one owns a thread and
 * walks the targets in order, which bounds the whole run to one config's worst case.
 */
object BypassProbe {

    private const val TIMEOUT_MS = 2_500
    private const val SPLIT_DELAY_MS = 20L
    private const val MAX_PARALLEL = 12
    private const val MAX_HELLO = 64 * 1024
    private const val TAG = "ThymusBypass"

    /** Two filters, two providers: Google's SNI filtering and Cloudflare's. */
    val DEFAULT_TARGETS = listOf(
        ProbeTarget("www.youtube.com"),
        ProbeTarget("youtubei.googleapis.com"),
        ProbeTarget("discord.com"),
    )

    /** The platform TLS stack, so the probe sends the same hello a browser would. */
    private val sslContext: SSLContext by lazy { SSLContext.getDefault() }

    /**
     * A real ClientHello built by the platform TLS stack for [host].
     *
     * A hand-made hello is rejected by some edges even without any filtering, which made
     * every config look broken. Letting `SSLEngine` produce it keeps the probe honest:
     * it offers the same versions, suites, key share and extensions as a normal client.
     * The handshake is never finished; a ServerHello is the only thing we need.
     */
    fun clientHello(host: String): ByteArray {
        val engine = sslContext.createSSLEngine(host, 443)
        engine.useClientMode = true
        engine.sslParameters = engine.sslParameters.apply {
            serverNames = listOf(SNIHostName(host))
            applicationProtocols = arrayOf("h2", "http/1.1")
        }
        engine.beginHandshake()

        val net = ByteBuffer.allocate(MAX_HELLO)
        engine.wrap(ByteBuffer.allocate(0), net)
        net.flip()
        val hello = ByteArray(net.remaining())
        net.get(hello)
        runCatching { engine.closeOutbound() }
        if (hello.isEmpty()) throw IOException("TLS stack produced no ClientHello")
        return hello
    }

    /** Resolves a target to an IPv4 address when possible: the tunnel itself is IPv4-only. */
    private fun resolve(host: String): InetAddress? = runCatching {
        val all = InetAddress.getAllByName(host)
        all.firstOrNull { it is Inet4Address } ?: all.firstOrNull()
    }.getOrNull()

    /** Sends one ClientHello through [strategy] and reports whether a ServerHello came back. */
    fun test(
        strategy: BypassStrategy,
        target: ProbeTarget,
        address: InetAddress? = null,
        timeoutMs: Int = TIMEOUT_MS,
    ): ProbeOutcome {
        val started = System.nanoTime()
        var socket: Socket? = null
        return try {
            val resolved = address ?: resolve(target.host)
                ?: throw IOException("cannot resolve ${target.host}")
            val created = Socket()
            socket = created
            // The app is normally excluded from the tunnel, so protecting the socket is
            // just a safety net; a false answer means it is already outside.
            ProbeGuard.protect?.let { guard -> runCatching { guard(created) } }
            created.tcpNoDelay = true
            created.connect(InetSocketAddress(resolved, target.port), timeoutMs)
            created.soTimeout = timeoutMs
            sendHello(created, strategy, target)
            val reply = ByteArray(6)
            readFully(created.getInputStream(), reply)
            // 0x16 handshake, 0x03 TLS major, 0x02 ServerHello.
            val ok = reply[0] == 0x16.toByte() &&
                reply[1] == 0x03.toByte() &&
                reply[5] == 0x02.toByte()
            ProbeOutcome(ok, elapsed(started))
        } catch (_: Throwable) {
            ProbeOutcome(false, elapsed(started))
        } finally {
            runCatching { socket?.close() }
        }
    }

    /** Tests every config in parallel and reports progress as each one finishes. */
    fun evaluate(
        profiles: List<BypassProfile>,
        targets: List<ProbeTarget> = DEFAULT_TARGETS,
        timeoutMs: Int = TIMEOUT_MS,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
    ): List<ProbeScore> {
        if (profiles.isEmpty()) return emptyList()
        val resolved = targets.mapNotNull { target ->
            resolve(target.host)?.let { target to it }
        }
        if (resolved.isEmpty()) return emptyList()
        val total = profiles.size
        val done = AtomicInteger(0)
        val pool = Executors.newFixedThreadPool(minOf(total, MAX_PARALLEL))
        return try {
            val futures = profiles.map { profile ->
                pool.submit(
                    Callable {
                        val strategy = profile.toStrategy()
                        var ok = 0
                        var latency = 0L
                        for ((target, address) in resolved) {
                            val outcome = test(strategy, target, address, timeoutMs)
                            Log.d(
                                TAG,
                                "probe ${profile.name} -> ${target.host} " +
                                    "(${address.hostAddress}): " +
                                    (if (outcome.ok) "ok" else "fail") + " ${outcome.latencyMs}ms",
                            )
                            if (outcome.ok) {
                                ok++
                                latency += outcome.latencyMs
                            }
                        }
                        onProgress?.invoke(done.incrementAndGet(), total)
                        val score = ProbeScore(
                            profile = profile,
                            ok = ok,
                            total = resolved.size,
                            latencyMs = if (ok == 0) Long.MAX_VALUE else latency / ok,
                        )
                        Log.d(TAG, "probe ${profile.name}: ${score.ok}/${score.total}")
                        score
                    },
                )
            }
            futures.mapNotNull { runCatching { it.get() }.getOrNull() }
        } finally {
            pool.shutdownNow()
        }
    }

    /** Most working targets wins; equal results are settled by lower latency. */
    fun rank(scores: List<ProbeScore>): ProbeScore? = scores
        .filter { it.ok > 0 }
        .maxWithOrNull(compareBy<ProbeScore>({ it.ok }, { -it.latencyMs }))

    private fun sendHello(socket: Socket, strategy: BypassStrategy, target: ProbeTarget) {
        val hello = clientHello(target.host)
        val out = socket.getOutputStream()
        val desync = strategy.active &&
            strategy.appliesToPort(target.port) &&
            strategy.appliesToHost(target.host)
        val recordLength = TlsClientHello.recordLength(hello)
        val cuts = if (desync) TlsClientHello.cuts(hello, strategy) else emptyList()
        if (cuts.isEmpty() || recordLength <= 1) {
            out.write(hello)
            out.flush()
            return
        }
        var start = 0
        for (cut in cuts) {
            out.write(TlsClientHello.record(hello, start, cut - start))
            out.flush()
            if (strategy.oob) {
                repeat(strategy.oobRepeats) { runCatching { socket.sendUrgentData(0) } }
            }
            Thread.sleep(SPLIT_DELAY_MS)
            start = cut
        }
        out.write(TlsClientHello.record(hello, start, recordLength - start))
        out.flush()
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read < 0) throw IOException("connection closed")
            offset += read
        }
    }

    private fun elapsed(started: Long): Long = (System.nanoTime() - started) / 1_000_000
}
