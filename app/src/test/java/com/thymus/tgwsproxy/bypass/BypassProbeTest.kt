package com.thymus.tgwsproxy.bypass

import com.thymus.tgwsproxy.core.TlsClientHello
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

class BypassProbeTest {

    private val server = ServerSocket(0)

    @After
    fun tearDown() {
        runCatching { server.close() }
    }

    @Test
    fun clientHelloIsAWellFormedRecordWithTheSni() {
        val hello = BypassProbe.clientHello("www.youtube.com")
        assertEquals(0x16, hello[0].toInt() and 0xFF)
        assertEquals(0x03, hello[1].toInt() and 0xFF)
        assertEquals(0x01, hello[5].toInt() and 0xFF)
        assertEquals(hello.size - 5, TlsClientHello.recordLength(hello))
        assertEquals("www.youtube.com", TlsClientHello.sniHost(hello))
    }

    @Test
    fun cutsLandInsideTheBlockedWord() {
        val hello = BypassProbe.clientHello("www.youtube.com")
        val host = TlsClientHello.sniRange(hello)!!
        val strategy = BypassStrategy(splitPositions = listOf(SplitPosition.Keyword), oob = true)
        val cut = TlsClientHello.cuts(hello, strategy).single() + 5
        assertTrue("the cut must fall inside the hostname", cut in host)
        assertTrue(
            "and inside the word the filter looks for",
            String(hello, cut - 3, 7, Charsets.US_ASCII).contains("youtube"),
        )
    }

    @Test
    fun framingKeepsEveryHandshakeByte() {
        val hello = BypassProbe.clientHello("discord.com")
        val strategy = BypassStrategy(
            splitPositions = listOf(SplitPosition.Offset(1), SplitPosition.Keyword),
        )
        val cuts = TlsClientHello.cuts(hello, strategy)
        assertEquals(2, cuts.size)

        var start = 0
        val rebuilt = ArrayList<Byte>()
        for (cut in cuts + TlsClientHello.recordLength(hello)) {
            val record = TlsClientHello.record(hello, start, cut - start)
            assertEquals(0x16, record[0].toInt() and 0xFF)
            assertEquals(cut - start, TlsClientHello.recordLength(record))
            rebuilt += record.copyOfRange(5, record.size).toList()
            start = cut
        }
        assertTrue(rebuilt.toByteArray().contentEquals(hello.copyOfRange(5, hello.size)))
    }

    @Test
    fun rankPrefersMoreWorkingTargetsThenLowerLatency() {
        val general = BypassPresets.byId("general")!!
        val alt = BypassPresets.byId("alt")!!
        val more = BypassProbe.rank(
            listOf(
                ProbeScore(general, ok = 2, total = 3, latencyMs = 100),
                ProbeScore(alt, ok = 3, total = 3, latencyMs = 900),
            ),
        )
        assertEquals(alt, more?.profile)

        val faster = BypassProbe.rank(
            listOf(
                ProbeScore(general, ok = 3, total = 3, latencyMs = 700),
                ProbeScore(alt, ok = 3, total = 3, latencyMs = 200),
            ),
        )
        assertEquals(alt, faster?.profile)
    }

    @Test
    fun rankIgnoresConfigsThatNeverGotThrough() {
        val general = BypassPresets.byId("general")!!
        assertTrue(
            BypassProbe.rank(
                listOf(ProbeScore(general, ok = 0, total = 3, latencyMs = Long.MAX_VALUE)),
            ) == null,
        )
    }

    @Test
    fun probeAcceptsAServerHello() {
        thread(isDaemon = true) {
            runCatching {
                server.accept().use { client ->
                    client.getInputStream().read(ByteArray(4096))
                    client.getOutputStream().write(
                        byteArrayOf(0x16, 0x03, 0x03, 0x00, 0x2A, 0x02),
                    )
                    client.getOutputStream().flush()
                }
            }
        }

        val outcome = BypassProbe.test(
            strategy = BypassStrategy(),
            target = ProbeTarget("127.0.0.1", server.localPort),
            address = InetAddress.getByName("127.0.0.1"),
            timeoutMs = 3000,
        )
        assertTrue(outcome.ok)
    }

    @Test
    fun probeRejectsASilentServer() {
        thread(isDaemon = true) {
            runCatching {
                server.accept().use { client ->
                    client.getInputStream().read(ByteArray(4096))
                    // No reply: exactly what a blocked handshake looks like.
                    Thread.sleep(1500)
                }
            }
        }

        val outcome = BypassProbe.test(
            strategy = BypassStrategy(),
            target = ProbeTarget("127.0.0.1", server.localPort),
            address = InetAddress.getByName("127.0.0.1"),
            timeoutMs = 600,
        )
        assertFalse(outcome.ok)
    }
}
