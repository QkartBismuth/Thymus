package com.thymus.tgwsproxy.core

import android.os.SystemClock
import android.util.Log
import com.thymus.tgwsproxy.bypass.BypassStrategy
import com.thymus.tgwsproxy.bypass.SplitPosition
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
 * stream, the first TLS ClientHello is rewritten into one or more TLS records with cuts
 * inside the SNI hostname. That defeats filters that inspect a single packet or a single
 * record; a DPI that reassembles handshake messages across records still sees the name,
 * and without root there is no way to reorder or fake packets.
 *
 * Device payload is queued and written by a dedicated writer task, never on the thread
 * that reads the TUN device: one slow server must not stall every other connection.
 */
internal class TcpRelay(
    private val tun: TunSink,
    first: Packets.Ip,
    private val strategy: BypassStrategy,
    private val onClosed: (TcpRelay) -> Unit,
    private val clock: () -> Long = { SystemClock.elapsedRealtime() },
) {
    private val clientIp = first.src
    private val clientPort = first.srcPort
    private val serverIp = first.dst
    private val serverPort = first.dstPort

    private val socket = Socket()
    private val lock = Object()

    /** Guards [pending] and [queuedSeq] only; never held while touching the socket. */
    private val queueLock = Object()
    private val pending = ArrayDeque<Chunk>()

    @Volatile private var closed = false
    @Volatile private var connected = false
    @Volatile var lastActive = SystemClock.elapsedRealtime()
    var key: String = ""

    private var clientSeq = (first.seq + 1) and MASK
    private var queuedSeq = (first.seq + 1) and MASK
    private var serverSeq = Random.nextInt().toLong() and MASK
    private var acked = serverSeq
    private var window = first.window.coerceIn(2048, 65535)
    private var finQueued = false

    /** Downstream segments the device has not acknowledged yet, newest last. */
    private val unacked = ArrayList<OutSegment>()
    private var rto = BASE_RTO_MS

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
                    send(Packets.TCP_SYN or Packets.TCP_ACK, EMPTY, serverSeq, clientSeq, mss = MSS)
                    serverSeq = (serverSeq + 1) and MASK
                    acked = serverSeq
                    connected = true
                    lock.notifyAll()
                }
                executor.execute { writerLoop() }
                executor.execute { upstreamLoop() }
                executor.execute { retransmitLoop() }
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
                    send(Packets.TCP_SYN or Packets.TCP_ACK, EMPTY, (serverSeq - 1) and MASK, clientSeq, mss = MSS)
                }
            }
            return
        }

        if (packet.flags and Packets.TCP_ACK != 0) {
            synchronized(lock) {
                if (seqDiff(packet.ack, acked) > 0) {
                    acked = packet.ack
                    rto = BASE_RTO_MS
                    unacked.removeAll { seqDiff(acked, endOf(it)) >= 0 }
                }
                window = packet.window.coerceIn(2048, 65535)
                lock.notifyAll()
            }
        }

        val payload = packet.payload
        val fin = packet.flags and Packets.TCP_FIN != 0
        if (payload.isNotEmpty() || fin) {
            var ackNow = false
            synchronized(queueLock) {
                when {
                    payload.isEmpty() -> {
                        if (!finQueued) {
                            finQueued = true
                            pending.addLast(Chunk(EMPTY, fin = true))
                            queueLock.notifyAll()
                        }
                    }
                    seqDiff(packet.seq, queuedSeq) == 0 -> {
                        queuedSeq = (queuedSeq + payload.size) and MASK
                        pending.addLast(Chunk(payload, fin = fin))
                        if (fin) finQueued = true
                        queueLock.notifyAll()
                    }
                    // A retransmission or a gap: acknowledge what we already hold so the
                    // device stops resending the part we have.
                    else -> ackNow = true
                }
            }
            if (ackNow) synchronized(lock) { send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq) }
        }
    }

    /** Writes queued device data to the upstream socket, in order, one chunk at a time. */
    private fun writerLoop() {
        val out = try {
            socket.getOutputStream()
        } catch (_: Throwable) {
            reset()
            return
        }
        var first = true
        while (true) {
            val chunk = synchronized(queueLock) {
                while (pending.isEmpty() && !closed) {
                    try {
                        queueLock.wait(1000)
                    } catch (_: InterruptedException) {
                        return
                    }
                }
                if (closed) null else pending.removeFirst()
            } ?: break

            try {
                if (chunk.fin) {
                    finishUpstream(out)
                    break
                }
                var finAfter = false
                if (first && strategy.active && strategy.appliesToPort(serverPort) &&
                    isTlsHandshake(chunk.data)
                ) {
                    val hello = gatherClientHello(chunk)
                    if (strategy.appliesToHost(sniHost(hello.data))) {
                        writeDesync(out, hello.data)
                    } else {
                        out.write(hello.data)
                        out.flush()
                    }
                    finAfter = hello.fin
                    synchronized(lock) {
                        clientSeq = (clientSeq + hello.data.size) and MASK
                        send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
                    }
                } else {
                    out.write(chunk.data)
                    out.flush()
                    synchronized(lock) {
                        clientSeq = (clientSeq + chunk.data.size) and MASK
                        send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
                    }
                }
                first = false
                if (finAfter) {
                    finishUpstream(out)
                    break
                }
            } catch (_: Throwable) {
                reset()
                return
            }
        }
    }

    private fun finishUpstream(out: OutputStream) {
        runCatching { out.flush() }
        runCatching { socket.shutdownOutput() }
        synchronized(lock) {
            clientSeq = (clientSeq + 1) and MASK
            send(Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
        }
    }

    /**
     * A ClientHello larger than one segment arrives in pieces. Wait for the rest of the
     * first TLS record so the whole handshake can be refragmented at once.
     */
    private fun gatherClientHello(first: Chunk): Gathered {
        var data = first.data
        var extra = 0
        var fin = false
        val deadline = clock() + HELLO_WAIT_MS
        while (data.size >= 5) {
            val recordEnd = 5 + u16(data, 3)
            if (recordEnd > MAX_HELLO || data.size >= recordEnd) break
            if (clock() >= deadline) break
            val next = synchronized(queueLock) {
                if (pending.isEmpty() && !closed) {
                    try {
                        queueLock.wait(50)
                    } catch (_: InterruptedException) {
                        return Gathered(data, extra, true)
                    }
                }
                if (closed) null else pending.removeFirstOrNull()
            }
            if (closed) break
            if (next == null) continue
            if (next.fin) {
                fin = true
                break
            }
            data += next.data
            extra += next.data.size
        }
        return Gathered(data, extra, fin)
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
                    unacked.add(OutSegment(serverSeq, chunk, fin = false, sentAt = clock()))
                    serverSeq = (serverSeq + size) and MASK
                }
                offset += size
            }
        }
        if (!closed) {
            synchronized(lock) {
                if (!closed) {
                    send(Packets.TCP_FIN or Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
                    unacked.add(OutSegment(serverSeq, EMPTY, fin = true, sentAt = clock()))
                    serverSeq = (serverSeq + 1) and MASK
                }
            }
            // Give the device a moment to acknowledge the FIN before tearing the socket down.
            runCatching { Thread.sleep(1500) }
        }
        close()
    }

    /**
     * Resends downstream segments the device has not acknowledged. Without this a single
     * dropped segment stalls the connection forever, because the device only ACKs what it
     * already has and we would never fill the hole.
     */
    private fun retransmitLoop() {
        while (!closed) {
            try {
                Thread.sleep(RETRANSMIT_TICK_MS)
            } catch (_: InterruptedException) {
                return
            }
            if (closed) return
            var giveUp = false
            synchronized(lock) {
                if (closed) return
                val now = clock()
                var resent = false
                for (segment in unacked) {
                    if (now - segment.sentAt < rto) continue
                    if (segment.attempts >= MAX_RETRIES) {
                        giveUp = true
                        break
                    }
                    segment.attempts++
                    segment.sentAt = now
                    val flags = if (segment.fin) {
                        Packets.TCP_FIN or Packets.TCP_ACK
                    } else {
                        Packets.TCP_ACK or Packets.TCP_PSH
                    }
                    send(flags, segment.data, segment.seq, clientSeq)
                    resent = true
                }
                if (resent && rto < MAX_RTO_MS) rto = minOf(rto * 2, MAX_RTO_MS)
            }
            if (giveUp) {
                reset()
                return
            }
        }
    }

    private fun endOf(segment: OutSegment): Long =
        (segment.seq + segment.data.size + if (segment.fin) 1 else 0) and MASK

    /** Blocks while more bytes are in flight than the device's receive window allows. */
    private fun awaitWindow() {
        synchronized(lock) {
            while (!closed && ((serverSeq - acked) and MASK) > window) {
                try {
                    lock.wait(1000)
                } catch (_: InterruptedException) {
                    return
                }
            }
        }
    }

    private fun send(flags: Int, payload: ByteArray, seq: Long, ack: Long, mss: Int = 0) {
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
                mss = mss,
            ),
        )
        lastActive = SystemClock.elapsedRealtime()
    }

    /**
     * Reframes the ClientHello into one or more TLS records according to the selected
     * strategy. A cut inside the blocked word hides it from per-fragment matching; the
     * out-of-band byte between records breaks reassembly, like zapret's `oob` + `midsld`.
     */
    private fun writeDesync(out: OutputStream, data: ByteArray) {
        val recordLength = if (data.size >= 5) u16(data, 3) else 0
        if (recordLength <= 1 || data.size < 5 + recordLength) {
            out.write(data)
            out.flush()
            return
        }
        val host = sniRange(data)
        val cuts = strategy.splitPositions
            .mapNotNull { resolveCut(it, data, host, recordLength) }
            .filter { it in 1 until recordLength }
            .distinct()
            .sorted()

        if (cuts.isEmpty()) {
            out.write(data)
            out.flush()
            return
        }

        var start = 0
        for (cut in cuts) {
            writeRecord(out, data, start, cut - start)
            if (strategy.oob) {
                // The server's TCP stack drops urgent bytes, but a DPI that reads the
                // payload literally sees a stray byte and loses the handshake.
                repeat(strategy.oobRepeats) { runCatching { socket.sendUrgentData(0) } }
            }
            runCatching { Thread.sleep(SPLIT_DELAY_MS) }
            start = cut
        }
        writeRecord(out, data, start, recordLength - start)

        val tail = 5 + recordLength
        if (data.size > tail) {
            out.write(data, tail, data.size - tail)
            out.flush()
        }
        Log.d(
            TAG,
            "ClientHello ${data.size}B: ${cuts.size + 1} TLS records" +
                (if (strategy.oob) " + OOB" else "") + ", cuts $cuts",
        )
    }

    private fun writeRecord(out: OutputStream, data: ByteArray, bodyOffset: Int, length: Int) {
        out.write(tlsRecord(data, bodyOffset, length))
        out.flush()
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

    /** Copy of the first record's header with a new length and a slice of its body. */
    private fun tlsRecord(source: ByteArray, bodyOffset: Int, length: Int): ByteArray {
        val record = ByteArray(5 + length)
        record[0] = 0x16
        record[1] = source[1]
        record[2] = source[2]
        record[3] = ((length shr 8) and 0xFF).toByte()
        record[4] = (length and 0xFF).toByte()
        source.copyInto(record, 5, 5 + bodyOffset, 5 + bodyOffset + length)
        return record
    }

    /** Byte range of the SNI hostname inside the ClientHello, or null when it cannot be parsed. */
    private fun sniRange(data: ByteArray): IntRange? {
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

    private fun sniHost(data: ByteArray): String? = sniRange(data)?.let { range ->
        String(data, range.first, range.last - range.first + 1, Charsets.US_ASCII)
    }

    private fun isTlsHandshake(payload: ByteArray): Boolean =
        payload.size >= 3 &&
            payload[0] == 0x16.toByte() &&
            payload[1] == 0x03.toByte()

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

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

    private fun reset() {
        if (!closed) {
            runCatching {
                synchronized(lock) {
                    send(Packets.TCP_RST or Packets.TCP_ACK, EMPTY, serverSeq, clientSeq)
                }
            }
        }
        close()
    }

    fun close() {
        if (closed) return
        closed = true
        runCatching { socket.close() }
        synchronized(lock) {
            unacked.clear()
            lock.notifyAll()
        }
        synchronized(queueLock) {
            pending.clear()
            queueLock.notifyAll()
        }
        onClosed(this)
    }

    val isClosed: Boolean get() = closed

    private class Chunk(val data: ByteArray, val fin: Boolean)

    private class Gathered(val data: ByteArray, val extra: Int, val fin: Boolean)

    private class OutSegment(
        val seq: Long,
        val data: ByteArray,
        val fin: Boolean,
        var sentAt: Long,
        var attempts: Int = 0,
    )

    private companion object {
        val EMPTY = ByteArray(0)
        const val MASK = 0xFFFFFFFFL
        const val CONNECT_TIMEOUT_MS = 10_000
        const val MSS = 1400
        const val RECEIVE_WINDOW = 65535
        const val SPLIT_DELAY_MS = 25L
        const val BASE_RTO_MS = 500L
        const val MAX_RTO_MS = 4000L
        const val RETRANSMIT_TICK_MS = 100L
        const val MAX_RETRIES = 8
        const val HELLO_WAIT_MS = 300L
        const val MAX_HELLO = 16 * 1024
        const val TAG = "ThymusBypass"

        /** Words the filter looks for; the ClientHello is cut inside one of them. */
        val SENSITIVE_TOKENS = listOf(
            "youtube", "youtu", "googlevideo", "googleapis", "ytimg", "ggpht",
            "discord", "telegram",
        )

        /** Wraparound-safe comparison of two 32-bit TCP sequence numbers. */
        fun seqDiff(a: Long, b: Long): Int = (a - b).toInt()
    }
}
