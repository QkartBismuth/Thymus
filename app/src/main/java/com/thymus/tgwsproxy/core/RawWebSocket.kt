package com.thymus.tgwsproxy.core

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Base64
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

class WsHandshakeException(val status: Int, message: String) : IOException(message)

/**
 * Minimal RFC 6455 client — binary frames only, no extensions. Written by hand instead
 * of using OkHttp so that framing, masking and back-pressure behave exactly like the
 * reference Python implementation (one MTProto packet per frame, explicit flush).
 */
class RawWebSocket private constructor(
    private val socket: Socket,
    private val input: InputStream,
    private val output: OutputStream,
) {
    @Volatile
    var closed: Boolean = false
        private set

    private val writeLock = Any()
    private val fragment = ByteArrayOutputStream()

    val isAlive: Boolean
        get() = !closed && !socket.isClosed && socket.isConnected

    fun send(data: ByteArray) {
        if (closed) throw IOException("WebSocket closed")
        val frame = buildFrame(OP_BINARY, data, masked = true)
        synchronized(writeLock) {
            output.write(frame)
            output.flush()
        }
    }

    fun sendBatch(parts: List<ByteArray>) {
        if (closed) throw IOException("WebSocket closed")
        synchronized(writeLock) {
            for (part in parts) output.write(buildFrame(OP_BINARY, part, masked = true))
            output.flush()
        }
    }

    /** Returns the next complete data message, or null when the peer closed the socket. */
    fun recv(): ByteArray? {
        while (!closed) {
            val frame = readFrame() ?: return null
            when (frame.opcode) {
                OP_CLOSE -> {
                    runCatching { sendControl(OP_CLOSE, frame.payload.copyOf(minOf(2, frame.payload.size))) }
                    closed = true
                    return null
                }

                OP_PING -> {
                    runCatching { sendControl(OP_PONG, frame.payload) }
                }

                OP_PONG -> Unit

                OP_CONT, OP_TEXT, OP_BINARY -> {
                    if (frame.fin && fragment.size() == 0) return frame.payload
                    fragment.write(frame.payload)
                    if (fragment.size() > MAX_MESSAGE_LEN) {
                        throw IOException("WS message too large: ${fragment.size()}")
                    }
                    if (!frame.fin) continue
                    val message = fragment.toByteArray()
                    fragment.reset()
                    return message
                }
            }
        }
        return null
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { sendControl(OP_CLOSE, ByteArray(0)) }
        runCatching { socket.close() }
    }

    fun closeQuietly() {
        runCatching { close() }
    }

    private fun sendControl(opcode: Int, payload: ByteArray) {
        val frame = buildFrame(opcode, payload, masked = true)
        synchronized(writeLock) {
            output.write(frame)
            output.flush()
        }
    }

    private class Frame(val fin: Boolean, val opcode: Int, val payload: ByteArray)

    private fun readFrame(): Frame? {
        val head = readFully(2) ?: return null
        val fin = (head[0].toInt() and 0x80) != 0
        val opcode = head[0].toInt() and 0x0F
        val masked = (head[1].toInt() and 0x80) != 0
        var length = (head[1].toInt() and 0x7F).toLong()

        if (length == 126L) {
            val ext = readFully(2) ?: return null
            length = ((ext[0].toInt() and 0xFF) shl 8 or (ext[1].toInt() and 0xFF)).toLong()
        } else if (length == 127L) {
            val ext = readFully(8) ?: return null
            length = 0
            for (b in ext) length = (length shl 8) or (b.toLong() and 0xFF)
        }
        if (length > MAX_MESSAGE_LEN) throw IOException("WS frame too large: $length")

        val maskKey = if (masked) readFully(4) ?: return null else null
        val payload = readFully(length.toInt()) ?: return null
        if (maskKey != null) xorMask(payload, maskKey)
        return Frame(fin, opcode, payload)
    }

    private fun readFully(size: Int): ByteArray? {
        val buf = ByteArray(size)
        var off = 0
        while (off < size) {
            val n = input.read(buf, off, size - off)
            if (n < 0) return null
            off += n
        }
        return buf
    }

    private fun buildFrame(opcode: Int, data: ByteArray, masked: Boolean): ByteArray {
        val length = data.size
        val out = ByteArrayOutputStream(length + 14)
        out.write(0x80 or opcode)

        val maskBit = if (masked) 0x80 else 0
        when {
            length < 126 -> out.write(maskBit or length)
            length < 65536 -> {
                out.write(maskBit or 126)
                out.write((length ushr 8) and 0xFF)
                out.write(length and 0xFF)
            }

            else -> {
                out.write(maskBit or 127)
                for (i in 7 downTo 0) out.write(((length.toLong() ushr (8 * i)) and 0xFF).toInt())
            }
        }

        if (masked) {
            val key = randomBytes(4)
            out.write(key)
            val copy = data.copyOf()
            xorMask(copy, key)
            out.write(copy)
        } else {
            out.write(data)
        }
        return out.toByteArray()
    }

    companion object {
        const val MAX_MESSAGE_LEN = 16 * 1024 * 1024

        private const val OP_CONT = 0x0
        private const val OP_TEXT = 0x1
        private const val OP_BINARY = 0x2
        private const val OP_CLOSE = 0x8
        private const val OP_PING = 0x9
        private const val OP_PONG = 0xA

        /**
         * Opens a TLS connection to [host]:443 (IP or DNS name), sends the WS upgrade
         * request for [domain] and reads the response.
         *
         * [sni] doubles as the TLS server name. When [verifyHostname] is false the
         * certificate chain is still validated, but the hostname is not — this mirrors
         * the "fronting" fallback of the reference implementation.
         */
        fun connect(
            host: String,
            domain: String,
            path: String = DcInfo.WS_PATH,
            sni: String = domain,
            verifyHostname: Boolean = true,
            connectTimeoutMs: Int = 8000,
            handshakeTimeoutMs: Int = 8000,
            addresses: List<java.net.InetAddress>? = null,
        ): RawWebSocket {
            var plain = Socket()
            try {
                plain = if (addresses != null) {
                    Dns.connectTo(addresses, host, 443, connectTimeoutMs)
                } else {
                    Dns.connect(host, 443, connectTimeoutMs)
                }
                plain.soTimeout = handshakeTimeoutMs

                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, null, null)
                val ssl = sslContext.socketFactory.createSocket(plain, sni, 443, true) as SSLSocket
                val params = ssl.sslParameters
                if (verifyHostname) params.endpointIdentificationAlgorithm = "HTTPS"
                params.serverNames = listOf(SNIHostName(sni))
                ssl.sslParameters = params
                ssl.soTimeout = handshakeTimeoutMs
                ssl.startHandshake()
                ssl.soTimeout = 0

                val input = BufferedInputStream(ssl.getInputStream(), 32 * 1024)
                val output = BufferedOutputStream(ssl.getOutputStream(), 32 * 1024)

                val key = Base64.getEncoder().encodeToString(randomBytes(16))
                val request = buildString {
                    append("GET ").append(path).append(" HTTP/1.1\r\n")
                    append("Host: ").append(domain).append("\r\n")
                    append("Upgrade: websocket\r\n")
                    append("Connection: Upgrade\r\n")
                    append("Sec-WebSocket-Key: ").append(key).append("\r\n")
                    append("Sec-WebSocket-Version: 13\r\n")
                    append("Sec-WebSocket-Protocol: binary\r\n")
                    append("\r\n")
                }
                output.write(request.toByteArray(Charsets.US_ASCII))
                output.flush()

                val statusLine = readLine(input) ?: throw WsHandshakeException(0, "empty WS response")
                val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                while (true) {
                    val line = readLine(input) ?: break
                    if (line.isEmpty()) break
                }
                if (status != 101) throw WsHandshakeException(status, statusLine)

                return RawWebSocket(ssl, input, output)
            } catch (t: Throwable) {
                runCatching { plain.close() }
                throw t
            }
        }

        private fun readLine(input: InputStream): String? {
            val sb = StringBuilder(128)
            while (true) {
                val b = input.read()
                if (b < 0) {
                    if (sb.isEmpty()) return null
                    break
                }
                if (b == '\n'.code) break
                if (b != '\r'.code) sb.append(b.toChar())
                if (sb.length > 8192) throw IOException("WS header line too long")
            }
            return sb.toString()
        }

        private fun xorMask(data: ByteArray, key: ByteArray) {
            for (i in data.indices) {
                data[i] = (data[i].toInt() xor key[i and 3].toInt()).toByte()
            }
        }
    }
}
