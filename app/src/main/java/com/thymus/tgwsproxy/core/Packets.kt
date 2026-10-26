package com.thymus.tgwsproxy.core

/**
 * Minimal IPv4 / TCP / UDP packet codec for the local VPN.
 *
 * The VPN terminates the device's TCP connections itself and re-opens them from the app,
 * so it needs to parse and build packets instead of just forwarding bytes. Only IPv4 is
 * handled; IPv6 traffic simply stays outside the tunnel.
 */
internal object Packets {
    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    const val TCP_FIN = 0x01
    const val TCP_SYN = 0x02
    const val TCP_RST = 0x04
    const val TCP_PSH = 0x08
    const val TCP_ACK = 0x10

    private var ipId = 1

    val EMPTY = ByteArray(0)

    /** A parsed transport packet. Fields that do not apply are zero. */
    class Ip(
        val src: ByteArray,
        val dst: ByteArray,
        val protocol: Int,
        val ttl: Int,
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val window: Int,
        val payload: ByteArray,
    )

    fun parse(data: ByteArray, length: Int): Ip? {
        if (length < 20) return null
        if (((data[0].toInt() shr 4) and 0x0F) != 4) return null
        val ihl = (data[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null
        val total = u16(data, 2)
        val end = if (total in ihl..length) total else length
        val protocol = data[9].toInt() and 0xFF
        val src = data.copyOfRange(12, 16)
        val dst = data.copyOfRange(16, 20)
        val ttl = data[8].toInt() and 0xFF
        return when (protocol) {
            PROTO_TCP -> parseTcp(data, ihl, end, src, dst, ttl)
            PROTO_UDP -> parseUdp(data, ihl, end, src, dst, ttl)
            else -> null
        }
    }

    private fun parseTcp(
        data: ByteArray,
        offset: Int,
        end: Int,
        src: ByteArray,
        dst: ByteArray,
        ttl: Int,
    ): Ip? {
        if (end - offset < 20) return null
        val srcPort = u16(data, offset)
        val dstPort = u16(data, offset + 2)
        val seq = u32(data, offset + 4)
        val ack = u32(data, offset + 8)
        val headerSize = ((data[offset + 12].toInt() shr 4) and 0x0F) * 4
        if (headerSize < 20 || offset + headerSize > end) return null
        val flags = data[offset + 13].toInt() and 0x3F
        val window = u16(data, offset + 14)
        val payload = data.copyOfRange(offset + headerSize, end)
        return Ip(src, dst, PROTO_TCP, ttl, srcPort, dstPort, seq, ack, flags, window, payload)
    }

    private fun parseUdp(
        data: ByteArray,
        offset: Int,
        end: Int,
        src: ByteArray,
        dst: ByteArray,
        ttl: Int,
    ): Ip? {
        if (end - offset < 8) return null
        val srcPort = u16(data, offset)
        val dstPort = u16(data, offset + 2)
        val udpLength = u16(data, offset + 4)
        val payloadEnd = if (udpLength in 8..(end - offset)) offset + udpLength else end
        val payload = data.copyOfRange(offset + 8, payloadEnd)
        return Ip(src, dst, PROTO_UDP, ttl, srcPort, dstPort, 0, 0, 0, 0, payload)
    }

    fun tcp(
        src: ByteArray,
        dst: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int,
        payload: ByteArray,
        mss: Int = 0,
    ): ByteArray {
        // A SYN-ACK without an MSS option makes the peer assume 536-byte segments.
        val headerSize = if (mss > 0) 24 else 20
        val total = 20 + headerSize + payload.size
        val packet = ByteArray(total)
        writeIpHeader(packet, total, PROTO_TCP, src, dst)
        put16(packet, 20, srcPort)
        put16(packet, 22, dstPort)
        put32(packet, 24, seq)
        put32(packet, 28, ack)
        packet[32] = ((headerSize / 4) shl 4).toByte()
        packet[33] = flags.toByte()
        put16(packet, 34, window)
        if (mss > 0) {
            packet[40] = 2 // kind: maximum segment size
            packet[41] = 4
            put16(packet, 42, mss)
        }
        payload.copyInto(packet, 20 + headerSize)
        val pseudo = pseudoSum(src, dst, PROTO_TCP, headerSize + payload.size)
        put16(packet, 36, checksum(packet, 20, headerSize + payload.size, pseudo))
        return packet
    }

    fun udp(
        src: ByteArray,
        dst: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val total = 28 + payload.size
        val packet = ByteArray(total)
        writeIpHeader(packet, total, PROTO_UDP, src, dst)
        put16(packet, 20, srcPort)
        put16(packet, 22, dstPort)
        put16(packet, 24, 8 + payload.size)
        // A zero UDP checksum is legal for IPv4 and saves a pass over the payload.
        put16(packet, 26, 0)
        payload.copyInto(packet, 28)
        return packet
    }

    /**
     * ICMP "port unreachable" quoting the datagram that was dropped.
     *
     * Used for QUIC: a client that is told the port is closed gives up on UDP/443 at once
     * instead of waiting for its own timeout, so the app falls back to TCP (where the
     * handshake split works) much sooner.
     */
    fun icmpPortUnreachable(
        remote: ByteArray,
        local: ByteArray,
        origSrc: ByteArray,
        origDst: ByteArray,
        origSrcPort: Int,
        origDstPort: Int,
        origPayloadLength: Int,
    ): ByteArray {
        val quote = ByteArray(28)
        writeIpHeader(quote, 28 + origPayloadLength, PROTO_UDP, origSrc, origDst)
        put16(quote, 20, origSrcPort)
        put16(quote, 22, origDstPort)
        put16(quote, 24, 8 + origPayloadLength)
        put16(quote, 26, 0)

        val icmpLength = 8 + quote.size
        val total = 20 + icmpLength
        val packet = ByteArray(total)
        writeIpHeader(packet, total, PROTO_ICMP, remote, local)
        packet[20] = 3 // destination unreachable
        packet[21] = 3 // port unreachable
        quote.copyInto(packet, 28)
        put16(packet, 22, checksum(packet, 20, icmpLength, 0))
        return packet
    }

    private fun writeIpHeader(packet: ByteArray, total: Int, protocol: Int, src: ByteArray, dst: ByteArray) {
        packet[0] = 0x45
        put16(packet, 2, total)
        put16(packet, 4, nextId())
        put16(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = protocol.toByte()
        src.copyInto(packet, 12)
        dst.copyInto(packet, 16)
        put16(packet, 10, checksum(packet, 0, 20, 0))
    }

    @Synchronized
    private fun nextId(): Int {
        ipId = (ipId + 1) and 0xFFFF
        return ipId
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int, initial: Long): Int {
        var sum = initial
        val end = offset + length
        var i = offset
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while ((sum shr 16) != 0L) sum = (sum and 0xFFFF) + (sum shr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun pseudoSum(src: ByteArray, dst: ByteArray, protocol: Int, length: Int): Long {
        var sum = 0L
        var i = 0
        while (i < 4) {
            sum += ((src[i].toInt() and 0xFF) shl 8) or (src[i + 1].toInt() and 0xFF)
            sum += ((dst[i].toInt() and 0xFF) shl 8) or (dst[i + 1].toInt() and 0xFF)
            i += 2
        }
        sum += protocol
        sum += length
        return sum
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun u32(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xFF) shl 24) or
            ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or
            (data[offset + 3].toLong() and 0xFF)

    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = ((value shr 8) and 0xFF).toByte()
        data[offset + 1] = (value and 0xFF).toByte()
    }

    private fun put32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = ((value shr 24) and 0xFF).toByte()
        data[offset + 1] = ((value shr 16) and 0xFF).toByte()
        data[offset + 2] = ((value shr 8) and 0xFF).toByte()
        data[offset + 3] = (value and 0xFF).toByte()
    }
}
