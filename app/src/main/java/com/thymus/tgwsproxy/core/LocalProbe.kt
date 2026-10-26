package com.thymus.tgwsproxy.core

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Minimal MTProto client used by the in-app self-test.
 *
 * Connects to our own loopback proxy, performs the obfuscated handshake with the
 * configured secret and sends unencrypted `req_pq_multi` requests. This exercises the
 * whole path — route selection, TLS, WebSocket, Telegram DC — on the device itself, so
 * the real latency of the proxy can be measured instead of guessed.
 *
 * Several pings can be sent over one connection, which is how Telegram measures the
 * proxy too: the first answer includes setting the tunnel up, the next ones are the
 * pure round-trip time.
 */
class LocalProbe(
    port: Int,
    secretHex: String,
    dc: Int,
    timeoutMs: Int = 20_000,
) : Closeable {

    private val socket = Socket()
    private val input: DataInputStream
    private val output: DataOutputStream
    private val sendCipher: CtrStream
    private val receiveCipher: CtrStream
    private var counter = 0L

    @Volatile
    private var closed = false

    init {
        val secret = secretHex.hexToBytes()
        socket.tcpNoDelay = true
        socket.connect(InetSocketAddress("127.0.0.1", port), 5000)
        socket.soTimeout = timeoutMs

        val prekey = randomBytes(32)
        val iv = randomBytes(16)
        val clientKey = sha256(prekey, secret)

        val handshake = randomBytes(64)
        prekey.copyInto(handshake, 8)
        iv.copyInto(handshake, 40)
        byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
            .copyInto(handshake, 56)
        handshake[60] = dc.toByte()
        handshake[61] = 0

        val tailCipher = CtrStream(clientKey, iv)
        tailCipher.skip(56)
        val tailKeystream = tailCipher.update(ByteArray(8))
        for (i in 0 until 8) {
            handshake[56 + i] =
                (handshake[56 + i].toInt() xor tailKeystream[i].toInt()).toByte()
        }

        output = DataOutputStream(socket.getOutputStream())
        output.write(handshake)
        output.flush()

        sendCipher = CtrStream(clientKey, iv).apply { skip(64) }
        val reversed = (prekey + iv).reversedCopy()
        receiveCipher = CtrStream(
            sha256(reversed.copyOfRange(0, 32), secret),
            reversed.copyOfRange(32, 48),
        )
        input = DataInputStream(socket.getInputStream())
    }

    /** Sends one `req_pq_multi` and returns its round-trip time in milliseconds. */
    fun ping(): Long {
        check(!closed) { "probe is closed" }
        counter += 1
        val started = System.currentTimeMillis()

        val body = ByteArray(20)
        body[0] = 0xF1.toByte()
        body[1] = 0x8E.toByte()
        body[2] = 0x7E.toByte()
        body[3] = 0xBE.toByte()
        randomBytes(16).copyInto(body, 4)

        val message = ByteArray(20 + body.size)
        val msgId = ((System.currentTimeMillis() / 1000L) shl 32) + counter
        for (i in 0 until 8) {
            message[8 + i] = ((msgId ushr (8 * i)) and 0xFF).toByte()
        }
        message[16] = body.size.toByte()
        body.copyInto(message, 20)

        val framed = ByteArray(4 + message.size)
        val frameLen = message.size
        framed[0] = frameLen.toByte()
        framed[1] = (frameLen ushr 8).toByte()
        framed[2] = (frameLen ushr 16).toByte()
        framed[3] = (frameLen ushr 24).toByte()
        message.copyInto(framed, 4)

        output.write(sendCipher.update(framed))
        output.flush()

        val prefix = ByteArray(4)
        input.readFully(prefix)
        val lengthBytes = receiveCipher.update(prefix)
        val responseLen = (lengthBytes[0].toInt() and 0xFF) or
            ((lengthBytes[1].toInt() and 0xFF) shl 8) or
            ((lengthBytes[2].toInt() and 0xFF) shl 16) or
            ((lengthBytes[3].toInt() and 0xFF) shl 24)
        check(responseLen in 20..1_000_000) { "unexpected response length $responseLen" }

        val response = ByteArray(responseLen)
        input.readFully(response)
        val plain = receiveCipher.update(response)
        val ctor = (plain[20].toInt() and 0xFF) or
            ((plain[21].toInt() and 0xFF) shl 8) or
            ((plain[22].toInt() and 0xFF) shl 16) or
            ((plain[23].toInt() and 0xFF) shl 24)
        check(ctor == 0x05162463) { "unexpected constructor 0x${ctor.toString(16)}" }
        return System.currentTimeMillis() - started
    }

    override fun close() {
        if (closed) return
        closed = true
        runCatching { socket.close() }
    }
}
