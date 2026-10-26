package com.thymus.tgwsproxy.core

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/** Byte-oriented tunnel to the Telegram datacenter (WebSocket or plain TCP). */
interface Tunnel : Closeable {
    fun send(data: ByteArray)
    fun recv(): ByteArray?
    /** False once the peer (or we) closed the connection; used to expire idle tunnels. */
    val isAlive: Boolean
}

class WsTunnel(private val ws: RawWebSocket) : Tunnel {
    override fun send(data: ByteArray) = ws.send(data)
    override fun recv(): ByteArray? = ws.recv()
    override fun close() = ws.closeQuietly()
    override val isAlive: Boolean get() = ws.isAlive
}

class TcpTunnel(private val socket: Socket) : Tunnel {
    private val input: InputStream = BufferedInputStream(socket.getInputStream(), 32 * 1024)
    private val output: OutputStream = BufferedOutputStream(socket.getOutputStream(), 32 * 1024)
    private val readBuffer = ByteArray(64 * 1024)

    override val isAlive: Boolean get() = !socket.isClosed && socket.isConnected

    override fun send(data: ByteArray) {
        output.write(data)
        output.flush()
    }

    override fun recv(): ByteArray? {
        val n = input.read(readBuffer)
        if (n < 0) return null
        return readBuffer.copyOf(n)
    }

    override fun close() {
        runCatching { socket.close() }
    }

    companion object {
        fun connect(host: String, port: Int, timeoutMs: Int = 10_000): TcpTunnel {
            val socket = Socket()
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            socket.soTimeout = 0
            return TcpTunnel(socket)
        }
    }
}
