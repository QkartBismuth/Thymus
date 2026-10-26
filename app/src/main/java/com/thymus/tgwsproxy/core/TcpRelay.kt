package com.thymus.tgwsproxy.core

import android.os.SystemClock
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ExecutorService
import kotlin.random.Random

/** Where a finished connection writes its packets: the VPN's TUN device. */
internal fun interface TunSink {
    fun write(packet: ByteArray)
}

/**
 * One terminated TCP connection.
 *
 * The device believes it talks to the real server; in fact it talks to this class, which
 * keeps a second, ordinary socket to the server. Because we own the device-side TCP
 * stream, the first TLS ClientHello can be split into two segments (at a byte inside the
 * SNI hostname) before it is written upstream — the cheapest DPI evasion that works
 * without root and raw sockets.
 */
internal class TcpRelay(
    private val tun: TunSink,
    first: Packets.Ip,
    private val desync: Boolean,
    private val onClosed: (TcpRelay) -> Unit,
) {
    private val clientIp = first.src
    private val clientPort = first.srcPort
    private val serverIp = first.dst
    private val serverPort = first.dstPort

    private val socket = Socket()
    private val lock = Object()

    @Volatile private var closed = false
    @Volatile private var connected = false
    @Volatile var lastActive = SystemClock.elapsedRealtime()
    var key: String = ""

    private var clientSeq = first.seq + 1
    private var serverSeq = Random.nextInt().toLong() and 0xFFFFFFFFL
    private var acked = serverSeq
    private var window = first.window.coerceIn(4096, 65535)
    private var desynced = false

    fun start(executor: ExecutorService) {
        executor.execute {
            try {
                socket.tcpNoDelay = true
                socket.connect(
                    InetSocketAddress(InetAddress.getByAddress(serverIp), serverPort),
                    CONNECT_TIMEOUT_MS,
                )
                synchronized(lock) {
                    if (closed) {
                        runCatching { socket.close() }
                        return@execute
                    }
                    send(Packets.TCP_SYN or Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
                    serverSeq = (serverSeq + 1) and 0xFFFFFFFFL
                    acked = serverSeq
                    connected = true
                    lock.notifyAll()
                }
                executor.execute { upstreamLoop() }
            } catch (_: Throwable) {
                reset()
            }
        }
    }

    fun onPacket(packet: Packets.Ip) {
        lastActive = SystemClock.elapsedRealtime()
        if (closed) return

        if (packet.flags and Packets.TCP_RST != 0) {
            close()
            return
        }

        if (packet.flags and Packets.TCP_SYN != 0) {
            // Retransmitted SYN: repeat the handshake answer instead of opening a second socket.
            if (connected) {
                synchronized(lock) {
                    send(Packets.TCP_SYN or Packets.TCP_ACK, EMPTY, serverSeq - 1, clientSeq)
                }
            }
            return
        }

        if (packet.flags and Packets.TCP_ACK != 0) {
            synchronized(lock) {
                if (packet.ack > acked) acked = packet.ack
                window = packet.window.coerceIn(1024, 65535)
                lock.notifyAll()
            }
        }

        val payload = packet.payload
        if (payload.isNotEmpty()) {
            when {
                packet.seq == clientSeq -> {
                    try {
                        val out = socket.getOutputStream()
                        if (desync && !desynced && serverPort == 443 && isTlsHandshake(payload)) {
                            desynced = true
                            writeSplit(out, payload)
                        } else {
                            out.write(payload)
                            out.flush()
                        }
                        clientSeq += payload.size
                        synchronized(lock) { send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq) }
                    } catch (_: Throwable) {
                        reset()
                        return
                    }
                }
                // A retransmission or a gap: acknowledge what we already have so the
                // device retransmits the missing bytes.
                else -> synchronized(lock) { send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq) }
            }
        }

        if (packet.flags and Packets.TCP_FIN != 0) {
            clientSeq += 1
            synchronized(lock) { send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq) }
            runCatching { socket.shutdownOutput() }
        }
    }

    private fun upstreamLoop() {
        val input = try {
            socket.getInputStream()
        } catch (_: Throwable) {
            close()
            return
        }
        val buffer = ByteArray(32 * 1024)
        while (!closed) {
            val read = try {
                input.read(buffer)
            } catch (_: Throwable) {
                break
            }
            if (read < 0) break
            var offset = 0
            while (offset < read && !closed) {
                val size = minOf(read - offset, MSS)
                awaitWindow()
                if (closed) return
                val chunk = buffer.copyOfRange(offset, offset + size)
                synchronized(lock) {
                    if (closed) return
                    send(Packets.TCP_ACK or Packets.TCP_PSH, chunk, serverSeq, clientSeq)
                    serverSeq = (serverSeq + size) and 0xFFFFFFFFL
                }
                offset += size
            }
        }
        if (!closed) {
            synchronized(lock) {
                if (!closed) {
                    send(Packets.TCP_FIN or Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
                    serverSeq = (serverSeq + 1) and 0xFFFFFFFFL
                }
            }
            // Give the device a moment to acknowledge the FIN before tearing the socket down.
            Thread.sleep(1500)
        }
        close()
    }

    /** Blocks while more bytes are in flight than the device's receive window allows. */
    private fun awaitWindow() {
        synchronized(lock) {
            while (!closed && serverSeq - acked > window.coerceAtMost(MAX_IN_FLIGHT)) {
                lock.wait(1000)
            }
        }
    }

    private fun send(flags: Int, payload: ByteArray, seq: Long, ack: Long) {
        tun.write(
            Packets.tcp(
                src = serverIp,
                dst = clientIp,
                srcPort = serverPort,
                dstPort = clientPort,
                seq = seq,
                ack = ack,
                flags = flags,
                window = RECEIVE_WINDOW,
                payload = payload,
            ),
        )
        lastActive = SystemClock.elapsedRealtime()
    }

    /**
     * Splits the ClientHello at a byte inside the SNI hostname, so neither TCP segment
     * carries the full blocked name. Falls back to a one-byte first segment.
     */
    private fun writeSplit(out: OutputStream, data: ByteArray) {
        val cut = sniCut(data) ?: 1
        if (cut <= 0 || cut >= data.size) {
            out.write(data)
            out.flush()
            return
        }
        out.write(data, 0, cut)
        out.flush()
        Thread.sleep(25)
        out.write(data, cut, data.size - cut)
        out.flush()
    }

    /** Offset inside the SNI name where the handshake can be cut, or null when unknown. */
    private fun sniCut(data: ByteArray): Int? {
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
                        return nameStart + 2
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

    private fun isTlsHandshake(payload: ByteArray): Boolean =
        payload.size >= 3 &&
            payload[0] == 0x16.toByte() &&
            payload[1] == 0x03.toByte()

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun reset() {
        if (!closed) {
            runCatching { synchronized(lock) { send(Packets.TCP_RST or Packets.TCP_ACK, EMPTY, serverSeq, clientSeq) } }
        }
        close()
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { socket.close() }
        synchronized(lock) { lock.notifyAll() }
        onClosed(this)
    }

    val isClosed: Boolean get() = closed

    private companion object {
        val EMPTY = ByteArray(0)
        const val CONNECT_TIMEOUT_MS = 10_000
        const val MSS = 1400
        const val RECEIVE_WINDOW = 65535
        const val MAX_IN_FLIGHT = 262144
    }
}
