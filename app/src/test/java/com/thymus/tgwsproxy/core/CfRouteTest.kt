package com.thymus.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Checks the Cloudflare-proxied fallback in isolation:
 *  1. our WS client can upgrade through a CF-proxied domain at all;
 *  2. a full ProxyEngine with an empty DC map (so only CF is possible)
 *     relays a real `req_pq_multi` and gets `resPQ`.
 *
 *     ./gradlew test -Dtgws.netTest=1
 */
class CfRouteTest {

    private val domains = listOf(
        "offshor.co.uk",
        "sorokdva.co.uk",
        "notelega.co.uk",
        "pomogite.co.uk",
        "sadnews.co.uk",
    )

    @Test
    fun wsUpgradeThroughCloudflare() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val errors = StringBuilder()
        var ok = false
        for (base in domains) {
            val domain = "kws2.$base"
            try {
                val ws = RawWebSocket.connect(domain, domain, DcInfo.WS_PATH, domain, true, 8000, 8000)
                ws.closeQuietly()
                ok = true
                break
            } catch (t: Throwable) {
                errors.append("$domain: ${t.javaClass.simpleName}: ${t.message}; ")
            }
        }
        assertTrue(errors.toString(), ok)
    }

    @Test
    fun diagnosticsReport() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val lines = java.util.concurrent.CopyOnWriteArrayList<String>()
        ProxyDiagnostics.run(
            ProxyConfig(
                secretHex = "000102030405060708090a0b0c0d0e0f",
                dcMap = DcInfo.DEFAULT_DC_MAP,
                cfDomains = domains,
                warmup = false,
            ),
        ) { lines.add(it) }
        println(lines.joinToString("\n"))
        val dcLines = lines.filter { it.startsWith("DC") }
        assertEquals(lines.joinToString("\n"), 5, dcLines.size)
        assertTrue(lines.joinToString("\n"), lines.any { it.startsWith("Локальный тест DC2") })
    }

    @Test
    fun localProbeMeasuresPing() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val secret = randomBytes(16).toHex()
        val engine = ProxyEngine(
            ProxyConfig(
                port = 0,
                secretHex = secret,
                dcMap = emptyMap(),
                cfDomains = domains,
                cfEnabled = true,
                tcpEnabled = false,
                warmup = false,
            ),
            log = {},
        )
        assertTrue(engine.start())
        try {
            LocalProbe(engine.boundPort, secret, 2).use { probe ->
                val setup = probe.ping()
                val rtt = probe.ping()
                println("setup=$setup ms, ping=$rtt ms")
                assertTrue("setup took $setup ms", setup in 1..25_000)
                assertTrue("ping took $rtt ms", rtt in 0..10_000)
            }
        } finally {
            engine.stop()
        }
    }

    @Test
    fun warmupReportsRoutes() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val logs = java.util.concurrent.CopyOnWriteArrayList<String>()
        val engine = ProxyEngine(
            ProxyConfig(
                port = 0,
                secretHex = randomBytes(16).toHex(),
                cfDomains = domains,
                warmup = true,
            ),
            log = { logs.add(it) },
        )
        assertTrue(engine.start())
        try {
            val deadline = System.currentTimeMillis() + 30_000
            while (System.currentTimeMillis() < deadline && logs.none { it.startsWith("Проверка:") }) {
                Thread.sleep(200)
            }
            println(logs.joinToString("\n"))
            assertTrue(logs.joinToString("\n"), logs.any { it.startsWith("Проверка:") })
        } finally {
            engine.stop()
        }
    }

    @Test
    fun pooledConnectionIsReused() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val logs = java.util.concurrent.CopyOnWriteArrayList<String>()
        val secret = randomBytes(16).toHex()
        val engine = ProxyEngine(
            ProxyConfig(
                port = 0,
                secretHex = secret,
                dcMap = emptyMap(),
                cfDomains = domains,
                cfEnabled = true,
                tcpEnabled = false,
                warmup = false,
            ),
            log = { logs.add(it) },
        )
        assertTrue(engine.start())
        try {
            LocalProbe(engine.boundPort, secret, 2).use { it.ping() }

            // After a successful connection the engine opens one spare tunnel in the
            // background; wait for it, then leave it idle to see whether Telegram keeps
            // an uninitialised WS open (the pool TTL relies on that).
            val deadline = System.currentTimeMillis() + 20_000
            while (System.currentTimeMillis() < deadline && engine.pooledCount == 0) {
                Thread.sleep(100)
            }
            assertEquals("no spare tunnel was prepared, logs:\n$logs", 1, engine.pooledCount)
            Thread.sleep(18_000)

            val started = System.currentTimeMillis()
            LocalProbe(engine.boundPort, secret, 2).use { probe ->
                val setup = probe.ping()
                println("setup from pool=$setup ms (18 s idle), logs:\n$logs")
                assertTrue("pooled setup took $setup ms", setup < 2_000)
            }
            assertTrue(logs.joinToString("\n"), logs.any { it.contains("готовое соединение") })
        } finally {
            engine.stop()
        }
    }

    @Test
    fun relaysThroughCloudflareOnly() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val logs = java.util.concurrent.CopyOnWriteArrayList<String>()
        val secret = randomBytes(16).toHex()
        val engine = ProxyEngine(
            ProxyConfig(
                port = 0,
                secretHex = secret,
                dcMap = emptyMap(),
                cfDomains = domains,
                cfEnabled = true,
                tcpEnabled = false,
                warmup = false,
            ),
            log = { logs.add(it) },
        )
        assertTrue("engine did not start: $logs", engine.start())
        try {
            val reply = E2eClient(engine.boundPort, secret).reqPqMulti(2)
            assertEquals("resPQ via CF, logs: $logs", 0x05162463, reply.constructor)
        } finally {
            engine.stop()
        }
    }
}
