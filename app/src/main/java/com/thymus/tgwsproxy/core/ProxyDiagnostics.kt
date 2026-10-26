package com.thymus.tgwsproxy.core

import java.net.InetSocketAddress
import java.net.Socket
import java.util.Collections
import java.util.Locale

/**
 * User-triggered route check: for every Telegram DC it probes the direct WebSocket,
 * the Cloudflare fallback and plain TCP, then prints one line per DC.
 *
 * After that it runs a self-test through the local proxy, which reports the real
 * time-to-first-answer and the steady-state ping — that is the number Telegram shows.
 *
 * Runs outside the proxy so it also works while the proxy is stopped, and tells the
 * user (and us) exactly which route their network allows and how fast it is.
 */
object ProxyDiagnostics {

    fun run(config: ProxyConfig, log: (String) -> Unit) {
        log("— проверка маршрутов —")
        val threads = (1..5).map { dc ->
            Thread({ log(probeDc(dc, config)) }, "tgws-diag").apply {
                isDaemon = true
                start()
            }
        }
        for (thread in threads) runCatching { thread.join(35_000) }
        selfTest(config, log)
        log("— проверка завершена —")
    }

    private fun probeDc(dc: Int, config: ProxyConfig): String {
        val parts = ArrayList<String>(3)
        parts.add("WS " + direct(dc, config.dcMap[dc]))
        parts.add("CF " + cloudflare(dc, config.cfDomains))
        parts.add("TCP " + tcp(dc))
        return "DC$dc: " + parts.joinToString(" · ")
    }

    private fun direct(dc: Int, mapped: String?): String {
        val candidates = ArrayList<Pair<String, () -> RawWebSocket>>()
        if (mapped != null) {
            for (domain in DcInfo.wsDomains(dc, false)) {
                candidates.add(
                    Pair("$domain@$mapped") {
                        RawWebSocket.connect(mapped, domain, DcInfo.WS_PATH, domain, true, 5000, 5000)
                    },
                )
            }
        }
        for (domain in DcInfo.wsDomains(dc, false)) {
            for (address in Dns.resolve(domain)) {
                val ip = address.hostAddress ?: continue
                if (ip == mapped) continue
                candidates.add(
                    Pair("$domain@$ip") {
                        RawWebSocket.connect(ip, domain, DcInfo.WS_PATH, domain, true, 5000, 5000)
                    },
                )
            }
        }
        if (candidates.isEmpty()) return "нет DC→IP"
        return race(candidates, 6000)
    }

    private fun cloudflare(dc: Int, domains: List<String>): String {
        val sample = domains.shuffled().take(6)
        if (sample.isEmpty()) return "выключен"
        val candidates = sample.map { base ->
            val domain = "kws$dc.$base"
            Pair(domain) {
                RawWebSocket.connect(
                    domain, domain, DcInfo.WS_PATH, domain, true, 6000, 6000,
                    Dns.resolveCf(domain),
                )
            }
        }
        return race(candidates, 10_000)
    }

    private fun tcp(dc: Int): String {
        val ip = DcInfo.DEFAULT_IPS[dc] ?: return "нет IP"
        val started = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(ip, 443), 5000)
            }
            "✓ $ip ${millis(System.currentTimeMillis() - started)}"
        } catch (t: Throwable) {
            "✗ $ip ${WsRace.shortError(t)}"
        }
    }

    private fun race(
        candidates: List<Pair<String, () -> RawWebSocket>>,
        windowMs: Long,
    ): String {
        val errors = Collections.synchronizedList(ArrayList<Pair<String, String>>())
        val started = System.currentTimeMillis()
        val winner = WsRace.run(candidates, windowMs, errors)
        if (winner != null) {
            winner.second.closeQuietly()
            return "✓ ${winner.first} ${millis(System.currentTimeMillis() - started)}"
        }
        val reason = WsRace.summarize(errors)
        return "✗ " + reason.ifEmpty { "нет ответа" }
    }

    /**
     * End-to-end test through a throw-away proxy instance: time to the first answer
     * (includes picking the route) and the ping of the next request on the same
     * connection. Both numbers come from this device and this network.
     */
    private fun selfTest(config: ProxyConfig, log: (String) -> Unit) {
        if (config.secretHex.length != 32) return
        log("— локальный тест —")
        val engine = ProxyEngine(
            config.copy(port = 0, host = "127.0.0.1", warmup = false),
            log = {},
        )
        if (!engine.start()) {
            log("Локальный тест: прокси не запустился")
            return
        }
        try {
            for (dc in listOf(2, 4)) {
                val started = System.currentTimeMillis()
                val probe = try {
                    LocalProbe(engine.boundPort, config.secretHex, dc)
                } catch (t: Throwable) {
                    log("Локальный тест DC$dc: ✗ ${WsRace.shortError(t)}")
                    continue
                }
                probe.use {
                    try {
                        it.ping()
                        val setup = System.currentTimeMillis() - started
                        val rtt = runCatching { it.ping() }.getOrNull()
                        val line = if (rtt != null) {
                            "Локальный тест DC$dc: ответ за ${millis(setup)}, пинг ${millis(rtt)}"
                        } else {
                            "Локальный тест DC$dc: ответ за ${millis(setup)}"
                        }
                        log(line)
                    } catch (t: Throwable) {
                        log("Локальный тест DC$dc: ✗ ${WsRace.shortError(t)}")
                    }
                }
            }
        } finally {
            engine.stop()
        }
    }

    private fun millis(value: Long): String =
        if (value >= 1000) String.format(Locale.US, "%.1f с", value / 1000.0) else "$value мс"
}
