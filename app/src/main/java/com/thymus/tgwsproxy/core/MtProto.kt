package com.thymus.tgwsproxy.core

/**
 * MTProto obfuscated-transport handshake handling.
 *
 * Telegram (with a `dd...` MTProto proxy secret) sends a 64-byte obfuscated init packet:
 *   0..8    random, must not be a reserved prefix
 *   8..40   prekey
 *   40..56  iv
 *   56..60  protocol tag (ef ef ef ef | ee ee ee ee | dd dd dd dd)
 *   60..62  dc id, little-endian signed (negative = media DC)
 *   62..64  random
 * The whole packet is AES-CTR encrypted with key = SHA256(prekey || secret), iv = iv.
 */
object MtProto {
    const val HANDSHAKE_LEN = 64
    const val SKIP_LEN = 8
    const val PREKEY_LEN = 32
    const val KEY_LEN = 32
    const val IV_LEN = 16
    const val PROTO_TAG_POS = 56
    const val DC_IDX_POS = 60

    private val PROTO_TAG_ABRIDGED = byteArrayOf(0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte())
    private val PROTO_TAG_INTERMEDIATE = byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
    private val PROTO_TAG_SECURE = byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte())

    const val PROTO_ABRIDGED_INT = 0xEFEFEFEF.toInt()
    const val PROTO_INTERMEDIATE_INT = 0xEEEEEEEE.toInt()
    const val PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD.toInt()

    private val RESERVED_FIRST_BYTES = setOf(0xEF.toByte())
    private val RESERVED_STARTS = listOf(
        "HEAD".toByteArray(),
        "POST".toByteArray(),
        "GET ".toByteArray(),
        byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte()),
        byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte()),
        byteArrayOf(0x16, 0x03, 0x01, 0x02),
        "OPTI".toByteArray(),
    )
    private val RESERVED_CONTINUE = byteArrayOf(0, 0, 0, 0)

    data class Handshake(
        val dc: Int,
        val isMedia: Boolean,
        val protoTag: ByteArray,
        val protoInt: Int,
        /** prekey (32) + iv (16), i.e. bytes 8..56 of the client packet. */
        val clientPrekeyIv: ByteArray,
    )

    fun parseHandshake(packet: ByteArray, secret: ByteArray): Handshake? {
        if (packet.size != HANDSHAKE_LEN) return null

        val prekeyIv = packet.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)
        val key = sha256(prekeyIv.copyOfRange(0, PREKEY_LEN), secret)
        val iv = prekeyIv.copyOfRange(PREKEY_LEN, PREKEY_LEN + IV_LEN)

        val plain = CtrStream(key, iv).update(packet)
        if (plain.size != HANDSHAKE_LEN) return null

        val tag = plain.copyOfRange(PROTO_TAG_POS, PROTO_TAG_POS + 4)
        val protoInt = when {
            tag.contentEquals(PROTO_TAG_ABRIDGED) -> PROTO_ABRIDGED_INT
            tag.contentEquals(PROTO_TAG_INTERMEDIATE) -> PROTO_INTERMEDIATE_INT
            tag.contentEquals(PROTO_TAG_SECURE) -> PROTO_PADDED_INTERMEDIATE_INT
            else -> return null
        }

        val dcIdx = ((plain[DC_IDX_POS].toInt() and 0xFF) or
                ((plain[DC_IDX_POS + 1].toInt() and 0xFF) shl 8)).toShort().toInt()
        val dc = if (dcIdx < 0) -dcIdx else dcIdx
        if (dc == 0) return null

        return Handshake(
            dc = dc,
            isMedia = dcIdx < 0,
            protoTag = tag,
            protoInt = protoInt,
            clientPrekeyIv = prekeyIv,
        )
    }

    /**
     * Builds the 64-byte init packet that is sent to the Telegram DC. It has the same
     * shape as a client handshake, but is encrypted with a fresh random key and carries
     * the requested `dcIdx` (negative for media).
     */
    fun buildRelayInit(protoTag: ByteArray, dcIdx: Int): ByteArray {
        var rnd: ByteArray
        do {
            rnd = randomBytes(HANDSHAKE_LEN)
        } while (
            rnd[0] in RESERVED_FIRST_BYTES ||
            RESERVED_STARTS.any { it.contentEquals(rnd.copyOfRange(0, 4)) } ||
            rnd.copyOfRange(4, 8).contentEquals(RESERVED_CONTINUE)
        )

        val key = rnd.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN)
        val iv = rnd.copyOfRange(SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)
        val encryptedFull = CtrStream(key, iv).update(rnd)

        val tailPlain = ByteArray(8)
        protoTag.copyInto(tailPlain, 0)
        tailPlain[4] = (dcIdx and 0xFF).toByte()
        tailPlain[5] = ((dcIdx ushr 8) and 0xFF).toByte()
        randomBytes(2).copyInto(tailPlain, 6)

        val result = rnd.copyOf(HANDSHAKE_LEN)
        for (i in 0 until 8) {
            val keystream = (encryptedFull[56 + i].toInt() xor rnd[56 + i].toInt()).toByte()
            result[56 + i] = (tailPlain[i].toInt() xor keystream.toInt()).toByte()
        }
        return result
    }

    /**
     * Builds the four AES-CTR streams used to re-encrypt the traffic:
     * client ciphertext -> plaintext -> relay ciphertext and back.
     */
    fun buildCrypto(handshake: Handshake, secret: ByteArray, relayInit: ByteArray): CryptoContext {
        val prekeyIv = handshake.clientPrekeyIv

        val clientDecKey = sha256(prekeyIv.copyOfRange(0, PREKEY_LEN), secret)
        val clientDecIv = prekeyIv.copyOfRange(PREKEY_LEN, PREKEY_LEN + IV_LEN)

        val reversed = prekeyIv.reversedCopy()
        val clientEncKey = sha256(reversed.copyOfRange(0, PREKEY_LEN), secret)
        val clientEncIv = reversed.copyOfRange(PREKEY_LEN, PREKEY_LEN + IV_LEN)

        val clientDec = CtrStream(clientDecKey, clientDecIv).apply { skip(HANDSHAKE_LEN) }
        val clientEnc = CtrStream(clientEncKey, clientEncIv)

        val relayEncKey = relayInit.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN)
        val relayEncIv = relayInit.copyOfRange(SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)

        val relayReversed = relayInit.copyOfRange(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN).reversedCopy()
        val tgDecKey = relayReversed.copyOfRange(0, KEY_LEN)
        val tgDecIv = relayReversed.copyOfRange(KEY_LEN, KEY_LEN + IV_LEN)

        val tgEnc = CtrStream(relayEncKey, relayEncIv).apply { skip(HANDSHAKE_LEN) }
        val tgDec = CtrStream(tgDecKey, tgDecIv)

        return CryptoContext(clientDec, clientEnc, tgEnc, tgDec)
    }
}

class CryptoContext(
    /** decrypts bytes coming from the Telegram client. */
    val clientDec: CtrStream,
    /** encrypts bytes going to the Telegram client. */
    val clientEnc: CtrStream,
    /** encrypts bytes going to the relay (WS / TCP). */
    val tgEnc: CtrStream,
    /** decrypts bytes coming from the relay. */
    val tgDec: CtrStream,
)
