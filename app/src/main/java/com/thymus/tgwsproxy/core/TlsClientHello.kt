package com.thymus.tgwsproxy.core

import com.thymus.tgwsproxy.bypass.BypassStrategy
import com.thymus.tgwsproxy.bypass.SplitPosition

/**
 * Parsing and reframing of the first TLS ClientHello.
 *
 * The live relay and the config probe both go through this object, so auto-selection
 * measures exactly the rewrite the tunnel will perform.
 */
internal object TlsClientHello {

    fun isHandshake(payload: ByteArray): Boolean =
        payload.size >= 3 &&
            payload[0] == 0x16.toByte() &&
            payload[1] == 0x03.toByte()

    fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    /** Declared body length of the first TLS record, or 0 when the header is missing. */
    fun recordLength(data: ByteArray): Int = if (data.size >= 5) u16(data, 3) else 0

    /**
     * Body offsets inside the first TLS record where the handshake should be cut,
     * sorted and de-duplicated. Empty when the record cannot be split.
     */
    fun cuts(data: ByteArray, strategy: BypassStrategy): List<Int> {
        val recordLength = recordLength(data)
        if (recordLength <= 1 || data.size < 5 + recordLength) return emptyList()
        val host = sniRange(data)
        return strategy.splitPositions
            .mapNotNull { resolveCut(it, data, host, recordLength) }
            .filter { it in 1 until recordLength }
            .distinct()
            .sorted()
    }

    /** Copy of the first record's header with a new length and a slice of its body. */
    fun record(source: ByteArray, bodyOffset: Int, length: Int): ByteArray {
        val record = ByteArray(5 + length)
        record[0] = 0x16
        record[1] = source[1]
        record[2] = source[2]
        record[3] = ((length shr 8) and 0xFF).toByte()
        record[4] = (length and 0xFF).toByte()
        source.copyInto(record, 5, 5 + bodyOffset, 5 + bodyOffset + length)
        return record
    }

    /** Byte range of the SNI hostname inside the ClientHello, or null when unparsable. */
    fun sniRange(data: ByteArray): IntRange? {
        return try {
            if (data.size < 9 || data[0] != 0x16.toByte() || data[5] != 0x01.toByte()) {
                null
            } else {
                var i = 9 + 2 + 32
                if (i >= data.size) return null
                i += 1 + (data[i].toInt() and 0xFF)
                if (i + 2 > data.size) return null
                i += 2 + u16(data, i)
                if (i >= data.size) return null
                i += 1 + (data[i].toInt() and 0xFF)
                if (i + 2 > data.size) return null
                i += 2
                val end = minOf(i + u16(data, i - 2), data.size)
                while (i + 4 <= end) {
                    val type = u16(data, i)
                    val length = u16(data, i + 2)
                    val body = i + 4
                    if (type == 0x0000 && body + 5 <= end) {
                        val nameLength = u16(data, body + 3)
                        val nameStart = body + 5
                        if (nameLength > 2 && nameStart + nameLength <= end) {
                            return nameStart until (nameStart + nameLength)
                        }
                        return null
                    }
                    i = body + length
                }
                null
            }
        } catch (_: Throwable) {
            null
        }
    }

    fun sniHost(data: ByteArray): String? = sniRange(data)?.let { range ->
        String(data, range.first, range.last - range.first + 1, Charsets.US_ASCII)
    }

    /** Resolves a strategy position into a body offset inside the first TLS record. */
    private fun resolveCut(
        position: SplitPosition,
        data: ByteArray,
        host: IntRange?,
        recordLength: Int,
    ): Int {
        val absolute = when (position) {
            SplitPosition.Keyword -> host?.let { keywordCut(data, it) }
            SplitPosition.Middle -> host?.let { it.first + (it.last - it.first + 1) / 2 }
            SplitPosition.HostStart -> host?.first
            is SplitPosition.Offset -> 5 + position.bytes
        } ?: (5 + recordLength / 2)
        return (absolute - 5).coerceIn(1, recordLength - 1)
    }

    /** Cuts inside the word the filter looks for, or in the middle of the hostname. */
    private fun keywordCut(data: ByteArray, host: IntRange): Int {
        val end = host.last + 1
        for (token in SENSITIVE_TOKENS) {
            val at = indexOfIgnoreCase(data, host.first, end, token)
            if (at >= 0) return at + token.length / 2
        }
        return host.first + (host.last - host.first + 1) / 2
    }

    /** Lowercase ASCII search inside [from, to), used to find a blocked word in the SNI. */
    private fun indexOfIgnoreCase(data: ByteArray, from: Int, to: Int, token: String): Int {
        var i = from
        while (i + token.length <= to) {
            var match = true
            for (j in token.indices) {
                val c = data[i + j].toInt() and 0xFF
                val lower = if (c in 'A'.code..'Z'.code) c + 32 else c
                if (lower != token[j].code) {
                    match = false
                    break
                }
            }
            if (match) return i
            i++
        }
        return -1
    }

    /** Words the filter looks for; the ClientHello is cut inside one of them. */
    private val SENSITIVE_TOKENS = listOf(
        "youtube", "youtu", "googlevideo", "googleapis", "ytimg", "ggpht",
        "discord", "telegram",
    )
}
