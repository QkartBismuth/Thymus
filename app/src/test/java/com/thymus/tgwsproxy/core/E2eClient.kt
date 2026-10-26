package com.thymus.tgwsproxy.core

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * A minimal fake Telegram client: performs the obfuscated handshake against the local
 * proxy and sends an unencrypted `req_pq_multi`, decoding the response.
 */
class E2eClient(
    private val port: Int,
    secretHex: String,
) {
    private val secret = secretHex.hexToBytes()

    class Reply(val authKeyId: ByteArray, val constructor: Int)

    fun reqPqMulti(dc: Int): Reply {
        Socket().use { socket ->
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress("127.0.0.1", port), 5000)
            socket.soTimeout = 25_000

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

            val out = DataOutputStream(socket.getOutputStream())
            out.write(handshake)
            out.flush()

            val sendCipher = CtrStream(clientKey, iv).apply { skip(64) }
            val reversed = (prekey + iv).reversedCopy()
            val receiveCipher = CtrStream(
                sha256(reversed.copyOfRange(0, 32), secret),
                reversed.copyOfRange(32, 48),
            )

            val body = ByteArray(20)
            body[0] = 0xF1.toByte()
            body[1] = 0x8E.toByte()
            body[2] = 0x7E.toByte()
            body[3] = 0xBE.toByte()
            randomBytes(16).copyInto(body, 4)

            val message = ByteArray(20 + body.size)
            val msgId = (System.currentTimeMillis() / 1000L) shl 32
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

            out.write(sendCipher.update(framed))
            out.flush()

            val input = DataInputStream(socket.getInputStream())
            val prefix = ByteArray(4)
            input.readFully(prefix)
            val lengthBytes = receiveCipher.update(prefix)
            val responseLen = (lengthBytes[0].toInt() and 0xFF) or
                ((lengthBytes[1].toInt() and 0xFF) shl 8) or
                ((lengthBytes[2].toInt() and 0xFF) shl 16) or
                ((lengthBytes[3].toInt() and 0xFF) shl 24)
            check(responseLen in 20..1_000_000) { "unexpected response length $responseLen" }

            val responseBody = ByteArray(responseLen)
            input.readFully(responseBody)
            val plain = receiveCipher.update(responseBody)
            val ctor = (plain[20].toInt() and 0xFF) or
                ((plain[21].toInt() and 0xFF) shl 8) or
                ((plain[22].toInt() and 0xFF) shl 16) or
                ((plain[23].toInt() and 0xFF) shl 24)
            return Reply(plain.copyOfRange(0, 8), ctor)
        }
    }
}
