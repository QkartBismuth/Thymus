package com.thymus.tgwsproxy.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import com.thymus.tgwsproxy.MainActivity
import com.thymus.tgwsproxy.R
import com.thymus.tgwsproxy.core.Packets
import com.thymus.tgwsproxy.core.TcpRelay
import com.thymus.tgwsproxy.core.TunSink
import com.thymus.tgwsproxy.data.Settings
import com.thymus.tgwsproxy.state.BypassState
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Local VPN that evades DPI without root.
 *
 * It terminates every TCP connection from the device, re-opens it as an ordinary socket
 * from this app and splits the first TLS ClientHello inside the SNI hostname. QUIC
 * (UDP 443) is dropped so YouTube falls back to TCP, and DNS is relayed through the VPN.
 * The app itself is excluded from the tunnel, so the MTProto proxy keeps working and the
 * relay sockets never loop back into the VPN.
 */
class BypassService : VpnService() {

    companion object {
        private const val CHANNEL_ID = "bypass_v2"
        private const val NOTIFICATION_ID = 1444
        const val ACTION_START = "com.thymus.tgwsproxy.action.BYPASS_START"
        const val ACTION_STOP = "com.thymus.tgwsproxy.action.BYPASS_STOP"
        private const val IDLE_TIMEOUT_MS = 120_000L
        private const val UDP_TIMEOUT_MS = 60_000

        fun start(context: Context) {
            val intent = Intent(context, BypassService::class.java).setAction(ACTION_START)
            context.startService(intent)
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, BypassService::class.java))
        }
    }

    private val flows = ConcurrentHashMap<String, TcpRelay>()
    private val udpFlows = ConcurrentHashMap<String, UdpRelay>()
    private val executor = Executors.newCachedThreadPool()
    private val handler = Handler(Looper.getMainLooper())

    private var tunnel: ParcelFileDescriptor? = null
    private var output: FileOutputStream? = null
    private val writeLock = Any()

    @Volatile private var running = false
    private var reader: Thread? = null

    private val janitor = object : Runnable {
        override fun run() {
            if (!running) return
            val now = SystemClock.elapsedRealtime()
            for (flow in flows.values) {
                if (flow.isClosed || now - flow.lastActive > IDLE_TIMEOUT_MS) {
                    flows.remove(flow.key)
                    flow.close()
                }
            }
            for (flow in udpFlows.values) {
                if (now - flow.lastActive > IDLE_TIMEOUT_MS) flow.close()
            }
            handler.postDelayed(this, 30_000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        if (!running) startTunnel()
        return START_STICKY
    }

    override fun onRevoke() {
        Settings.setBypassEnabled(this, false)
        shutdown()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    private fun startTunnel() {
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(1500)
            .addAddress("10.111.222.1", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
        // Keep this app outside its own tunnel: the proxy and the relay sockets must not loop.
        runCatching { builder.addDisallowedApplication(packageName) }

        val fd = try {
            builder.establish()
        } catch (_: Throwable) {
            null
        }
        if (fd == null) {
            BypassState.error.value = getString(R.string.bypass_error)
            Settings.setBypassEnabled(this, false)
            stopSelf()
            return
        }

        tunnel = fd
        output = FileOutputStream(fd.fileDescriptor)
        running = true
        startForeground(NOTIFICATION_ID, buildNotification())
        BypassState.running.value = true
        BypassState.error.value = null

        reader = Thread({ readLoop(fd) }, "bypass-tun").apply {
            priority = Thread.MAX_PRIORITY
            start()
        }
        handler.postDelayed(janitor, 30_000)
    }

    private fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        while (running) {
            val read = try {
                input.read(buffer)
            } catch (_: Throwable) {
                break
            }
            if (read <= 0) continue
            val packet = Packets.parse(buffer, read) ?: continue
            when (packet.protocol) {
                Packets.PROTO_TCP -> handleTcp(packet)
                Packets.PROTO_UDP -> handleUdp(packet)
            }
        }
    }

    private fun handleTcp(packet: Packets.Ip) {
        val key = keyOf(packet)
        val syn = packet.flags and Packets.TCP_SYN != 0 && packet.flags and Packets.TCP_ACK == 0
        if (syn) {
            val existing = flows[key]
            if (existing != null && !existing.isClosed) return
            val relay = TcpRelay(
                tun = TunSink { writePacket(it) },
                first = packet,
                desync = Settings.isBypassDesync(this),
                onClosed = { closed -> flows.remove(closed.key) },
            )
            relay.key = key
            flows[key] = relay
            relay.start(executor)
        } else {
            flows[key]?.onPacket(packet)
        }
    }

    /**
     * QUIC is dropped on purpose: it is what YouTube uses by default, and a TCP
     * connection can be desynced while QUIC cannot. Everything else keeps a small
     * per-flow socket, which is enough for DNS and Discord voice.
     */
    private fun handleUdp(packet: Packets.Ip) {
        if (packet.dstPort == 443) return
        val key = keyOf(packet)
        val existing = udpFlows[key]
        if (existing != null) {
            existing.send(packet.payload)
            return
        }
        val relay = UdpRelay(key, packet)
        udpFlows[key] = relay
        relay.start()
        relay.send(packet.payload)
    }

    private inner class UdpRelay(private val key: String, private val first: Packets.Ip) {
        private val socket = DatagramSocket()
        @Volatile var lastActive = SystemClock.elapsedRealtime()
        @Volatile private var closed = false

        fun start() {
            socket.connect(InetAddress.getByAddress(first.dst), first.dstPort)
            socket.soTimeout = UDP_TIMEOUT_MS
            executor.execute {
                val buffer = ByteArray(4096)
                while (!closed) {
                    try {
                        val response = DatagramPacket(buffer, buffer.size)
                        socket.receive(response)
                        lastActive = SystemClock.elapsedRealtime()
                        writePacket(
                            Packets.udp(
                                src = first.dst,
                                dst = first.src,
                                srcPort = first.dstPort,
                                dstPort = first.srcPort,
                                payload = response.data.copyOf(response.length),
                            ),
                        )
                    } catch (_: java.net.SocketTimeoutException) {
                        // Keep the flow for the next datagram.
                    } catch (_: Throwable) {
                        break
                    }
                }
                close()
            }
        }

        fun send(payload: ByteArray) {
            lastActive = SystemClock.elapsedRealtime()
            runCatching { socket.send(DatagramPacket(payload, payload.size)) }
        }

        fun close() {
            if (closed) return
            closed = true
            runCatching { socket.close() }
            udpFlows.remove(key)
        }
    }

    private fun writePacket(packet: ByteArray) {
        val stream = output ?: return
        synchronized(writeLock) {
            runCatching { stream.write(packet) }
        }
    }

    private fun keyOf(packet: Packets.Ip): String =
        "${packet.srcPort}:${packet.dstPort}:${packet.src.contentHashCode()}:${packet.dst.contentHashCode()}"

    private fun shutdown() {
        running = false
        handler.removeCallbacks(janitor)
        reader?.interrupt()
        reader = null
        for (flow in flows.values) flow.close()
        flows.clear()
        runCatching { output?.close() }
        output = null
        runCatching { tunnel?.close() }
        tunnel = null
        executor.shutdownNow()
        BypassState.running.value = false
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun createChannel() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.bypass_channel),
            NotificationManager.IMPORTANCE_MIN,
        ).apply {
            setShowBadge(false)
            setSound(null, null)
            enableVibration(false)
            lockscreenVisibility = Notification.VISIBILITY_SECRET
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_proxy)
            .setContentTitle(getString(R.string.bypass_notification))
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .build()
    }
}
