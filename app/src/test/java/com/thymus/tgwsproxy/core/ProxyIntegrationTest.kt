package com.thymus.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * End-to-end test against the real Telegram DC: a fake Telegram client talks to the
 * local proxy, the proxy opens a WebSocket to kws2.web.telegram.org and relays an
 * unencrypted `req_pq_multi`, which must be answered with `resPQ`.
 *
 * Disabled by default because it needs unrestricted access to Telegram:
 *     ./gradlew test -Dtgws.netTest=1
 */
class ProxyIntegrationTest {

    @Test
    fun relaysReqPqMultiToTelegram() {
        assumeTrue(
            "network test disabled, run with -Dtgws.netTest=1",
            System.getProperty("tgws.netTest") == "1",
        )

        val secret = randomBytes(16)
        val logs = CopyOnWriteArrayList<String>()
        val engine = ProxyEngine(
            ProxyConfig(
                port = 0,
                secretHex = secret.toHex(),
                dcMap = mapOf(2 to "149.154.167.220"),
                cfEnabled = false,
                warmup = false,
            ),
            log = { logs.add(it) },
        )

        assertTrue("engine did not start: $logs", engine.start())
        try {
            Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress("127.0.0.1", engine.boundPort), 5000)
                socket.soTimeout = 20_000

                val prekey = randomBytes(32)
                val iv = randomBytes(16)
                val clientKey = sha256(prekey, secret)

                // 1. Obfuscated handshake: only bytes 56..64 are encrypted.
                val handshake = randomBytes(64)
                prekey.copyInto(handshake, 8)
                iv.copyInto(handshake, 40)
                byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
                    .copyInto(handshake, 56)
                handshake[60] = 2
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

                // 2. Client-side stream ciphers (same derivation as Telegram uses).
                val sendCipher = CtrStream(clientKey, iv).apply { skip(64) }
                val reversed = (prekey + iv).reversedCopy()
                val receiveCipher = CtrStream(
                    sha256(reversed.copyOfRange(0, 32), secret),
                    reversed.copyOfRange(32, 48),
                )

                // 3. Unencrypted MTProto req_pq_multi inside an intermediate-transport frame.
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
                val bodyLen = body.size
                message[16] = bodyLen.toByte()
                message[17] = (bodyLen ushr 8).toByte()
                message[18] = (bodyLen ushr 16).toByte()
                message[19] = (bodyLen ushr 24).toByte()
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

                // 4. The server answers with resPQ.
                val input = DataInputStream(socket.getInputStream())
                val prefix = ByteArray(4)
                input.readFully(prefix)
                val lengthBytes = receiveCipher.update(prefix)
                val responseLen = (lengthBytes[0].toInt() and 0xFF) or
                    ((lengthBytes[1].toInt() and 0xFF) shl 8) or
                    ((lengthBytes[2].toInt() and 0xFF) shl 16) or
                    ((lengthBytes[3].toInt() and 0xFF) shl 24)
                assertTrue("unexpected response length $responseLen, logs: $logs", responseLen in 20..1_000_000)

                val responseBody = ByteArray(responseLen)
                input.readFully(responseBody)
                val plain = receiveCipher.update(responseBody)

                val authKeyIdEmpty = plain.copyOfRange(0, 8).all { it.toInt() == 0 }
                val ctor = (plain[20].toInt() and 0xFF) or
                    ((plain[21].toInt() and 0xFF) shl 8) or
                    ((plain[22].toInt() and 0xFF) shl 16) or
                    ((plain[23].toInt() and 0xFF) shl 24)

                assertTrue("expected an unencrypted response, logs: $logs", authKeyIdEmpty)
                assertEquals("resPQ constructor", 0x05162463, ctor)
            }
        } finally {
            engine.stop()
        }
    }
}
