package com.thymus.tgwsproxy.core

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal val SECURE_RANDOM = SecureRandom()

fun randomBytes(size: Int): ByteArray = ByteArray(size).also { SECURE_RANDOM.nextBytes(it) }

fun sha256(vararg parts: ByteArray): ByteArray {
    val md = MessageDigest.getInstance("SHA-256")
    for (part in parts) md.update(part)
    return md.digest()
}

/**
 * AES-128-CTR keystream, matching pycryptodome `modes.CTR` (16-byte big-endian counter),
 * which MTProto obfuscated transport uses.
 *
 * CTR is symmetric, so the same class is used for both directions; each stream instance
 * belongs to exactly one direction and is never shared between threads.
 */
class CtrStream(key: ByteArray, iv: ByteArray) {
    private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }

    fun update(data: ByteArray): ByteArray = cipher.update(data) ?: ByteArray(0)

    fun update(data: ByteArray, offset: Int, length: Int): ByteArray =
        cipher.update(data, offset, length) ?: ByteArray(0)

    /** Fast-forwards the keystream without allocating a full buffer in the caller. */
    fun skip(bytes: Int) {
        if (bytes > 0) cipher.update(ByteArray(bytes))
    }
}

fun ByteArray.toHex(): String {
    val out = StringBuilder(size * 2)
    for (b in this) {
        val v = b.toInt() and 0xFF
        out.append("0123456789abcdef"[v ushr 4])
        out.append("0123456789abcdef"[v and 0x0F])
    }
    return out.toString()
}

fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "odd hex length" }
    val out = ByteArray(length / 2)
    for (i in out.indices) {
        val hi = Character.digit(this[i * 2], 16)
        val lo = Character.digit(this[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) { "invalid hex" }
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

fun ByteArray.reversedCopy(): ByteArray = ByteArray(size) { this[size - 1 - it] }
