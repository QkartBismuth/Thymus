package com.thymus.tgwsproxy.core

/**
 * Splits an outgoing re-encrypted MTProto byte stream into individual transport
 * packets, so every WS frame carries exactly one packet (this is what the Telegram
 * WebSocket endpoint expects). Ported 1:1 from `MsgSplitter` in the reference project.
 *
 * The length header is not encrypted in the obfuscated transport, therefore packet
 * boundaries are read from the *plaintext* buffer while the emitted bytes come from
 * the ciphertext buffer.
 */
class MsgSplitter(private val protoInt: Int) {

    private var cipher = ByteArray(8192)
    private var plain = ByteArray(8192)
    private var cipherLen = 0
    private var plainLen = 0
    private var disabled = false

    fun split(chunk: ByteArray, plainChunk: ByteArray): List<ByteArray> {
        if (chunk.isEmpty()) return emptyList()
        if (disabled) return listOf(chunk)

        append(chunk, plainChunk)

        val parts = ArrayList<ByteArray>(2)
        var offset = 0
        while (offset < cipherLen) {
            val packetLen = nextPacketLen(offset, cipherLen - offset)
            if (packetLen == null) break
            if (packetLen <= 0) {
                parts.add(cipher.copyOfRange(offset, cipherLen))
                offset = cipherLen
                disabled = true
                break
            }
            parts.add(cipher.copyOfRange(offset, offset + packetLen))
            offset += packetLen
        }

        if (offset > 0) {
            dropFront(offset)
        }
        return parts
    }

    fun flush(): ByteArray? {
        if (cipherLen == 0) return null
        val tail = cipher.copyOfRange(0, cipherLen)
        cipherLen = 0
        plainLen = 0
        return tail
    }

    private fun nextPacketLen(offset: Int, available: Int): Int? {
        if (available <= 0) return null
        return when (protoInt) {
            MtProto.PROTO_ABRIDGED_INT -> nextAbridgedLen(offset, available)
            MtProto.PROTO_INTERMEDIATE_INT,
            MtProto.PROTO_PADDED_INTERMEDIATE_INT -> nextIntermediateLen(offset, available)
            else -> 0
        }
    }

    private fun nextAbridgedLen(offset: Int, available: Int): Int? {
        val first = plain[offset].toInt() and 0xFF
        val payloadLen: Int
        val headerLen: Int
        if (first == 0x7F || first == 0xFF) {
            if (available < 4) return null
            payloadLen = ((plain[offset + 1].toInt() and 0xFF) or
                    ((plain[offset + 2].toInt() and 0xFF) shl 8) or
                    ((plain[offset + 3].toInt() and 0xFF) shl 16)) * 4
            headerLen = 4
        } else {
            payloadLen = (first and 0x7F) * 4
            headerLen = 1
        }
        if (payloadLen <= 0) return 0
        val packetLen = headerLen + payloadLen
        return if (available < packetLen) null else packetLen
    }

    private fun nextIntermediateLen(offset: Int, available: Int): Int? {
        if (available < 4) return null
        val raw = (plain[offset].toInt() and 0xFF) or
                ((plain[offset + 1].toInt() and 0xFF) shl 8) or
                ((plain[offset + 2].toInt() and 0xFF) shl 16) or
                ((plain[offset + 3].toInt() and 0xFF) shl 24)
        val payloadLen = raw and 0x7FFFFFFF
        if (payloadLen <= 0) return 0
        val packetLen = 4 + payloadLen
        return if (available < packetLen) null else packetLen
    }

    private fun append(cipherChunk: ByteArray, plainChunk: ByteArray) {
        cipher = ensure(cipher, cipherLen + cipherChunk.size)
        plain = ensure(plain, plainLen + plainChunk.size)
        cipherChunk.copyInto(cipher, cipherLen)
        cipherLen += cipherChunk.size

        // The plaintext buffer is only used for header parsing; keep it in sync.
        val n = minOf(plainChunk.size, cipherChunk.size)
        plainChunk.copyInto(plain, plainLen, 0, n)
        plainLen += n
    }

    private fun dropFront(count: Int) {
        val cipherLeft = cipherLen - count
        if (cipherLeft > 0) cipher.copyInto(cipher, 0, count, cipherLen)
        cipherLen = cipherLeft

        val plainDrop = minOf(count, plainLen)
        val plainLeft = plainLen - plainDrop
        if (plainLeft > 0) plain.copyInto(plain, 0, plainDrop, plainLen)
        plainLen = plainLeft
    }

    private fun ensure(buf: ByteArray, capacity: Int): ByteArray {
        if (buf.size >= capacity) return buf
        var newSize = buf.size
        while (newSize < capacity) newSize *= 2
        return buf.copyOf(newSize)
    }
}
