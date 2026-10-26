package com.thymus.tgwsproxy.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Checks the hand-built IPv4/TCP/UDP/ICMP packets before they ever reach a real device. */
class PacketTests {

    private val client = byteArrayOf(10, 111, 222.toByte(), 1)
    private val server = byteArrayOf(93, 184.toByte(), 216.toByte(), 34)

    @Test
    fun tcpPacketHasValidIpAndTcpChecksums() {
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val packet = Packets.tcp(
            src = server,
            dst = client,
            srcPort = 443,
            dstPort = 50000,
            seq = 0x11223344L,
            ack = 0x55667788L,
            flags = Packets.TCP_ACK or Packets.TCP_PSH,
            window = 65535,
            payload = payload,
        )

        assertEquals(0xFFFF, sum(packet, 0, 20, 0))
        assertEquals(0xFFFF, sum(packet, 20, 20 + payload.size, pseudo(server, client, Packets.PROTO_TCP, 20 + payload.size)))

        val parsed = Packets.parse(packet, packet.size)
        assertNotNull(parsed)
        requireNotNull(parsed)
        assertArrayEquals(server, parsed.src)
        assertArrayEquals(client, parsed.dst)
        assertEquals(Packets.PROTO_TCP, parsed.protocol)
        assertEquals(443, parsed.srcPort)
        assertEquals(50000, parsed.dstPort)
        assertEquals(0x11223344L, parsed.seq)
        assertEquals(0x55667788L, parsed.ack)
        assertEquals(Packets.TCP_ACK or Packets.TCP_PSH, parsed.flags)
        assertEquals(65535, parsed.window)
        assertArrayEquals(payload, parsed.payload)
    }

    @Test
    fun emptyAckIsTwentyBytesLong() {
        val packet = Packets.tcp(client, server, 50000, 443, 1, 2, Packets.TCP_ACK, 1024, Packets.EMPTY)
        assertEquals(40, packet.size)
        assertEquals(40, ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF))
        assertEquals(0xFFFF, sum(packet, 20, 20, pseudo(client, server, Packets.PROTO_TCP, 20)))
    }

    @Test
    fun synAckCarriesMssOption() {
        val packet = Packets.tcp(
            src = server,
            dst = client,
            srcPort = 443,
            dstPort = 50000,
            seq = 1,
            ack = 2,
            flags = Packets.TCP_SYN or Packets.TCP_ACK,
            window = 65535,
            payload = Packets.EMPTY,
            mss = 1400,
        )
        assertEquals(44, packet.size)
        assertEquals(6, (packet[32].toInt() shr 4) and 0x0F)
        assertEquals(2, packet[40].toInt())
        assertEquals(4, packet[41].toInt())
        assertEquals(1400, ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF))
        assertEquals(0xFFFF, sum(packet, 20, 24, pseudo(server, client, Packets.PROTO_TCP, 24)))
        assertEquals(0, requireNotNull(Packets.parse(packet, packet.size)).payload.size)
    }

    @Test
    fun udpPacketHasValidIpHeaderAndOptionalChecksum() {
        val payload = byteArrayOf(0x12, 0x34, 0x01, 0x00)
        val packet = Packets.udp(server, client, 53, 33333, payload)
        assertEquals(32, packet.size)
        assertEquals(0xFFFF, sum(packet, 0, 20, 0))

        val parsed = Packets.parse(packet, packet.size)
        assertNotNull(parsed)
        requireNotNull(parsed)
        assertEquals(Packets.PROTO_UDP, parsed.protocol)
        assertEquals(53, parsed.srcPort)
        assertEquals(33333, parsed.dstPort)
        assertArrayEquals(payload, parsed.payload)
    }

    @Test
    fun icmpPortUnreachableQuotesTheOriginalDatagram() {
        val packet = Packets.icmpPortUnreachable(
            remote = server,
            local = client,
            origSrc = client,
            origDst = server,
            origSrcPort = 55555,
            origDstPort = 443,
            origPayloadLength = 1200,
        )

        // Outer IPv4 (20) + ICMP header (8) + quoted IPv4 header (20) + quoted UDP header (8).
        assertEquals(56, packet.size)
        assertEquals(Packets.PROTO_ICMP, packet[9].toInt() and 0xFF)
        assertEquals(0xFFFF, sum(packet, 0, 20, 0))
        assertEquals(0xFFFF, sum(packet, 20, 36, 0))
        assertEquals(3, packet[20].toInt())
        assertEquals(3, packet[21].toInt())

        // Quoted packet: source/destination are the device and the server, ports are the flow.
        assertArrayEquals(client, packet.copyOfRange(40, 44))
        assertArrayEquals(server, packet.copyOfRange(44, 48))
        assertEquals(55555, ((packet[48].toInt() and 0xFF) shl 8) or (packet[49].toInt() and 0xFF))
        assertEquals(443, ((packet[50].toInt() and 0xFF) shl 8) or (packet[51].toInt() and 0xFF))
    }

    @Test
    fun parsesIpv4HeaderWithOptions() {
        // IHL = 6: the IP header carries four bytes of options, so TCP starts at offset 24.
        val base = Packets.tcp(client, server, 40000, 443, 10, 20, Packets.TCP_ACK, 4096, "abc".toByteArray())
        val packet = ByteArray(base.size + 4)
        base.copyInto(packet, 0, 0, 20)
        packet[0] = 0x46
        // Router-alert style padding options.
        packet[20] = 1
        packet[21] = 1
        packet[22] = 1
        packet[23] = 1
        base.copyInto(packet, 24, 20, base.size)
        packet[2] = ((packet.size shr 8) and 0xFF).toByte()
        packet[3] = (packet.size and 0xFF).toByte()
        packet[10] = 0
        packet[11] = 0
        val ipFix = sum(packet, 0, 20, 0).inv() and 0xFFFF
        packet[10] = ((ipFix shr 8) and 0xFF).toByte()
        packet[11] = (ipFix and 0xFF).toByte()
        packet[40] = 0
        packet[41] = 0
        val tcpFix = sum(packet, 24, 23, pseudo(client, server, Packets.PROTO_TCP, 23)).inv() and 0xFFFF
        packet[40] = ((tcpFix shr 8) and 0xFF).toByte()
        packet[41] = (tcpFix and 0xFF).toByte()

        val parsed = Packets.parse(packet, packet.size)
        assertNotNull(parsed)
        requireNotNull(parsed)
        assertEquals(10L, parsed.seq)
        assertArrayEquals("abc".toByteArray(), parsed.payload)
    }

    @Test
    fun rejectsNonIpv4AndTruncatedPackets() {
        assertNull(Packets.parse(ByteArray(40), 40))
        val packet = Packets.tcp(client, server, 1, 2, 0, 0, Packets.TCP_ACK, 100, Packets.EMPTY)
        assertNull(Packets.parse(packet, 12))
        // Header claims 60 bytes but the buffer is 20.
        assertNull(Packets.parse(packet, 20))
        assertTrue(packet.isNotEmpty())
    }

    private fun pseudo(src: ByteArray, dst: ByteArray, protocol: Int, length: Int): Int {
        var total = 0
        for (i in 0 until 4 step 2) {
            total += ((src[i].toInt() and 0xFF) shl 8) or (src[i + 1].toInt() and 0xFF)
            total += ((dst[i].toInt() and 0xFF) shl 8) or (dst[i + 1].toInt() and 0xFF)
        }
        total += protocol
        total += length
        return total
    }

    /** One's complement sum over a region; a correct checksum makes it 0xFFFF. */
    private fun sum(data: ByteArray, offset: Int, length: Int, initial: Int): Int {
        var total = initial
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            total += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) total += (data[i].toInt() and 0xFF) shl 8
        while ((total shr 16) != 0) total = (total and 0xFFFF) + (total shr 16)
        return total
    }
}
