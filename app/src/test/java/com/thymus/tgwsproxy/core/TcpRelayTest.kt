package com.thymus.tgwsproxy.core

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import java.util.concurrent.Executors

/**
 * Drives a relay through a hand-made TCP conversation against a loopback server, so the
 * sequence-number handling is checked without a phone.
 */
class TcpRelayTest {

    private val executor = Executors.newCachedThreadPool()
    private val server = ServerSocket(0)
    private val packets = Collections.synchronizedList(mutableListOf<ByteArray>())
    private val clientIp = byteArrayOf(10, 111, 222.toByte(), 1)
    private val serverIp = byteArrayOf(127, 0, 0, 1)
    private val clientPort = 40123
    private val serverPort = server.localPort
    private val clientIsn = 1000L

    @After
    fun tearDown() {
        runCatching { server.close() }
        executor.shutdownNow()
    }

    @Test
    fun completesHandshakeAndRelaysBothDirections() {
        val relay = relay(desync = false)
        relay.start(executor)
        val upstream = server.accept()
        upstream.soTimeout = 3000

        val synAck = await { p -> p.flags and Packets.TCP_SYN != 0 }
        assertEquals(Packets.TCP_SYN or Packets.TCP_ACK, synAck.flags)
        assertEquals(clientIsn + 1, synAck.ack)
        val serverIsn = synAck.seq

        relay.onPacket(
            packet(
                seq = clientIsn + 1,
                ack = serverIsn + 1,
                flags = Packets.TCP_ACK or Packets.TCP_PSH,
                payload = "hello".toByteArray(),
            ),
        )
        assertEquals("hello", readExactly(upstream, 5))

        val ack = await { p -> p.flags == Packets.TCP_ACK && p.ack == clientIsn + 6 }
        assertEquals(serverIsn + 1, ack.seq)

        upstream.getOutputStream().write("world".toByteArray())
        upstream.getOutputStream().flush()
        val down = await { p -> p.payload.isNotEmpty() }
        assertEquals("world", String(down.payload))
        assertEquals(serverIsn + 1, down.seq)
        assertEquals(clientIsn + 6, down.ack)

        // The device acknowledges the downstream data; nothing else should be needed.
        relay.onPacket(packet(seq = clientIsn + 6, ack = serverIsn + 6, flags = Packets.TCP_ACK, payload = Packets.EMPTY))
        assertFalse(relay.isClosed)
        relay.close()
        assertTrue(relay.isClosed)
        runCatching { upstream.close() }
    }

    @Test
    fun splitsTheClientHelloInsideTheHostname() {
        val relay = relay(desync = true)
        relay.start(executor)
        val upstream = server.accept()
        upstream.soTimeout = 3000
        val synAck = await { p -> p.flags and Packets.TCP_SYN != 0 }

        val hello = clientHello("rutracker.org")
        relay.onPacket(
            packet(
                seq = clientIsn + 1,
                ack = synAck.seq + 1,
                flags = Packets.TCP_ACK or Packets.TCP_PSH,
                payload = hello,
            ),
        )

        val first = ByteArray(hello.size)
        val firstRead = upstream.getInputStream().read(first)
        val rest = readExactly(upstream, hello.size - firstRead)
        val joined = String(first.copyOf(firstRead), Charsets.ISO_8859_1) + rest
        assertTrue("handshake was not split", firstRead < hello.size)
        assertFalse(
            "the whole hostname went out in the first segment",
            String(first.copyOf(firstRead), Charsets.ISO_8859_1).contains("rutracker.org"),
        )
        assertTrue(
            "the handshake did not survive the split",
            joined.contains("rutracker.org"),
        )
        relay.close()
        runCatching { upstream.close() }
    }

    @Test
    fun retransmittedSegmentIsAcknowledgedWithoutDuplicatingData() {
        val relay = relay(desync = false)
        relay.start(executor)
        val upstream = server.accept()
        upstream.soTimeout = 3000
        val synAck = await { p -> p.flags and Packets.TCP_SYN != 0 }

        val data = packet(
            seq = clientIsn + 1,
            ack = synAck.seq + 1,
            flags = Packets.TCP_ACK or Packets.TCP_PSH,
            payload = "abc".toByteArray(),
        )
        relay.onPacket(data)
        assertEquals("abc", readExactly(upstream, 3))
        relay.onPacket(data) // duplicate

        upstream.soTimeout = 300
        var duplicated = false
        try {
            duplicated = upstream.getInputStream().read() >= 0
        } catch (_: java.net.SocketTimeoutException) {
            // Expected: the relay must not write the same bytes twice.
        }
        assertFalse("duplicate data reached the server", duplicated)
        upstream.soTimeout = 3000

        upstream.getOutputStream().write("z".toByteArray())
        upstream.getOutputStream().flush()
        val down = await { p -> p.payload.isNotEmpty() }
        assertEquals("z", String(down.payload))
        relay.close()
        runCatching { upstream.close() }
    }

    @Test
    fun retransmitsDataTheDeviceNeverAcknowledges() {
        var now = 0L
        val relay = TcpRelay(
            tun = TunSink { packets.add(it) },
            first = Packets.Ip(
                clientIp, serverIp, Packets.PROTO_TCP, 64,
                clientPort, serverPort, clientIsn, 0, Packets.TCP_SYN, 65535, Packets.EMPTY,
            ),
            desync = false,
            onClosed = {},
            clock = { now },
        )
        relay.start(executor)
        val upstream = server.accept()
        upstream.soTimeout = 3000
        await { p -> p.flags and Packets.TCP_SYN != 0 }

        upstream.getOutputStream().write("lost".toByteArray())
        upstream.getOutputStream().flush()
        val first = await { p -> p.payload.isNotEmpty() }
        assertEquals("lost", String(first.payload))

        now += 1000 // past the 500 ms retransmission timeout
        val resent = awaitCount(2) { p -> p.payload.isNotEmpty() }
        assertEquals(first.seq, resent.seq)
        assertEquals("lost", String(resent.payload))
        relay.close()
        runCatching { upstream.close() }
    }

    @Test
    fun resetIsSentWhenTheServerIsUnreachable() {
        val closed = ServerSocket(0)
        val deadPort = closed.localPort
        closed.close()
        val relay = TcpRelay(
            tun = TunSink { packets.add(it) },
            first = Packets.Ip(
                clientIp, serverIp, Packets.PROTO_TCP, 64,
                clientPort, deadPort, clientIsn, 0, Packets.TCP_SYN, 65535, Packets.EMPTY,
            ),
            desync = false,
            onClosed = {},
        )
        relay.start(executor)
        val reset = await { p -> p.flags and Packets.TCP_RST != 0 }
        assertTrue(reset.flags and Packets.TCP_RST != 0)
        assertTrue(relay.isClosed)
    }

    private fun relay(desync: Boolean) = TcpRelay(
        tun = TunSink { packets.add(it) },
        first = Packets.Ip(
            clientIp, serverIp, Packets.PROTO_TCP, 64,
            clientPort, serverPort, clientIsn, 0, Packets.TCP_SYN, 65535, Packets.EMPTY,
        ),
        desync = desync,
        onClosed = {},
    )

    private fun packet(seq: Long, ack: Long, flags: Int, payload: ByteArray) = Packets.Ip(
        clientIp, serverIp, Packets.PROTO_TCP, 64,
        clientPort, serverPort, seq, ack, flags, 65535, payload,
    )

    private fun await(predicate: (Packets.Ip) -> Boolean): Packets.Ip {
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline) {
            val snapshot = synchronized(packets) { packets.toList() }
            for (bytes in snapshot) {
                val parsed = Packets.parse(bytes, bytes.size) ?: continue
                if (predicate(parsed)) return parsed
            }
            Thread.sleep(5)
        }
        throw AssertionError("no matching packet; got ${packets.size}")
    }

    private fun awaitCount(count: Int, predicate: (Packets.Ip) -> Boolean): Packets.Ip {
        val deadline = System.currentTimeMillis() + 5000
        while (System.currentTimeMillis() < deadline) {
            val matches = synchronized(packets) {
                packets.mapNotNull { Packets.parse(it, it.size) }.filter(predicate)
            }
            if (matches.size >= count) return matches[count - 1]
            Thread.sleep(5)
        }
        throw AssertionError("expected $count matching packets")
    }

    private fun readExactly(socket: Socket, size: Int): String {
        val buffer = ByteArray(size)
        var read = 0
        while (read < size) {
            val n = socket.getInputStream().read(buffer, read, size - read)
            if (n < 0) break
            read += n
        }
        return String(buffer, 0, read, Charsets.ISO_8859_1)
    }

    /** Minimal but structurally valid TLS 1.2 ClientHello carrying one SNI name. */
    private fun clientHello(host: String): ByteArray {
        val name = host.toByteArray(Charsets.ISO_8859_1)
        val sni = ByteArray(5 + name.size)
        sni[0] = ((3 + name.size) shr 8).toByte()
        sni[1] = ((3 + name.size) and 0xFF).toByte()
        sni[2] = 0
        sni[3] = (name.size shr 8).toByte()
        sni[4] = (name.size and 0xFF).toByte()
        name.copyInto(sni, 5)
        val extensions = ByteArray(4 + sni.size + 6)
        extensions[0] = 0
        extensions[1] = 0 // server_name
        extensions[2] = (sni.size shr 8).toByte()
        extensions[3] = (sni.size and 0xFF).toByte()
        sni.copyInto(extensions, 4)
        val tail = 4 + sni.size
        extensions[tail] = 0
        extensions[tail + 1] = 0x2b // supported_versions
        extensions[tail + 2] = 0
        extensions[tail + 3] = 3
        extensions[tail + 4] = 2
        extensions[tail + 5] = 3

        val body = ByteArray(2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + extensions.size)
        var i = 0
        body[i++] = 3; body[i++] = 3 // TLS 1.2
        i += 32 // random
        body[i++] = 0 // session id
        body[i++] = 0; body[i++] = 2 // cipher suites length
        body[i++] = 0x13; body[i++] = 0x01
        body[i++] = 1; body[i++] = 0 // compression: null
        body[i++] = (extensions.size shr 8).toByte()
        body[i++] = (extensions.size and 0xFF).toByte()
        extensions.copyInto(body, i)

        val handshake = ByteArray(4 + body.size)
        handshake[0] = 1
        handshake[1] = (body.size shr 16).toByte()
        handshake[2] = (body.size shr 8).toByte()
        handshake[3] = (body.size and 0xFF).toByte()
        body.copyInto(handshake, 4)

        val record = ByteArray(5 + handshake.size)
        record[0] = 0x16
        record[1] = 3
        record[2] = 1
        record[3] = (handshake.size shr 8).toByte()
        record[4] = (handshake.size and 0xFF).toByte()
        handshake.copyInto(record, 5)
        return record
    }
}
