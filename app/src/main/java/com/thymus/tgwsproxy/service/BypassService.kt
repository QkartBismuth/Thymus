package com.thymus.tgwsproxy.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import com.thymus.tgwsproxy.MainActivity
import com.thymus.tgwsproxy.R
import com.thymus.tgwsproxy.bypass.BypassConfigs
import com.thymus.tgwsproxy.bypass.BypassProfile
import com.thymus.tgwsproxy.bypass.BypassStrategy
import com.thymus.tgwsproxy.core.Packets
import com.thymus.tgwsproxy.core.TcpRelay
import com.thymus.tgwsproxy.core.TunSink
import com.thymus.tgwsproxy.data.Settings
import com.thymus.tgwsproxy.state.BypassState
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Local VPN that tries to evade DPI without root.
 *
 * It terminates every TCP connection from the device, re-opens it as an ordinary socket
 * from this app and reframes the first TLS ClientHello inside the SNI hostname. QUIC
 * (UDP 443) and DNS are relayed through the VPN. The app itself is excluded from the
 * tunnel, so the MTProto proxy keeps working and the relay sockets never loop back.
 *
 * This is best-effort evasion, not a tunnel: a DPI that reassembles TLS records and
 * blocks UDP 443 cannot be bypassed from userspace without root.
 */
class BypassService : VpnService() {

    companion object {
        private const val CHANNEL_ID = "bypass_v2"
        private const val NOTIFICATION_ID = 1444
        const val ACTION_START = "com.thymus.tgwsproxy.action.BYPASS_START"
        const val ACTION_STOP = "com.thymus.tgwsproxy.action.BYPASS_STOP"
        const val ACTION_RELOAD = "com.thymus.tgwsproxy.action.BYPASS_RELOAD"
        private const val IDLE_TIMEOUT_MS = 120_000L
        private const val UDP_TIMEOUT_MS = 60_000
        private const val TELEGRAM_PACKAGE = "org.telegram.messenger"
        private const val MAX_TCP_FLOWS = 256
        private const val MAX_UDP_FLOWS = 256
        private const val TAG = "ThymusBypass"

        fun start(context: Context) {
            val intent = Intent(context, BypassService::class.java).setAction(ACTION_START)
            try {
                context.startService(intent)
            } catch (_: Throwable) {
                Settings.setBypassEnabled(context, false)
                BypassState.error.value = context.getString(R.string.bypass_error)
            }
        }

        fun stop(context: Context) {
            // A VpnService is bound by the system, so stopService() alone can leave the
            // tunnel up. ACTION_STOP runs shutdown() and stopSelf() inside the service.
            val intent = Intent(context, BypassService::class.java).setAction(ACTION_STOP)
            try {
                context.startService(intent)
            } catch (_: Throwable) {
                context.stopService(Intent(context, BypassService::class.java))
            }
        }

        /**
         * Applies a newly selected config to connections opened from now on. Existing
         * flows keep the strategy they started with, so a switch never breaks a live
         * download.
         */
        fun reload(context: Context) {
            val intent = Intent(context, BypassService::class.java).setAction(ACTION_RELOAD)
            runCatching { context.startService(intent) }
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

    @Volatile private var profile: BypassProfile = BypassProfile(
        id = "general",
        name = "General",
        description = "",
        splitPositions = listOf("midsld"),
        oob = true,
    )

    /** Snapshot for new connections; [applyProfile] swaps both fields together. */
    @Volatile private var strategy: BypassStrategy = profile.toStrategy()

    private fun applyProfile(value: BypassProfile) {
        profile = value
        strategy = value.toStrategy()
    }

    private val janitor = object : Runnable {
        override fun run() {
            if (!running) return
            val now = SystemClock.elapsedRealtime()
            for (flow in flows.values) {
                if (flow.isClosed || now - flow.lastActive > IDLE_TIMEOUT_MS) {
                    flows.remove(flow.key, flow)
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
        // A sticky restart must not resurrect a tunnel the user has switched off.
        if (!Settings.isBypassEnabled(this)) {
            stopSelf()
            return START_NOT_STICKY
        }
        val loaded = BypassConfigs.selected(this)
        applyProfile(loaded)
        if (intent?.action == ACTION_RELOAD && running) {
            Log.d(TAG, "config reload: ${loaded.name} (${loaded.splitPositions}, oob=${loaded.oob})")
            return START_STICKY
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
        // Reuse the resolvers the phone already trusts. Forcing 1.1.1.1 breaks on networks
        // where public DNS is blocked or redirected, which is exactly the case here.
        val resolvers = upstreamDnsServers()
        if (resolvers.isEmpty()) {
            builder.addDnsServer("1.1.1.1")
            builder.addDnsServer("8.8.8.8")
        } else {
            resolvers.forEach { builder.addDnsServer(it) }
        }
        // Keep this app outside its own tunnel: the proxy and the relay sockets must not loop.
        runCatching { builder.addDisallowedApplication(packageName) }
        // Telegram already reaches its DCs through the local MTProto proxy. Routing it
        // through a userspace TCP relay as well would only slow it down.
        runCatching { builder.addDisallowedApplication(TELEGRAM_PACKAGE) }

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
        applyProfile(BypassConfigs.selected(this))
        Log.d(TAG, "config: ${profile.name} (${profile.splitPositions}, oob=${profile.oob})")
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

    /** IPv4 resolvers of the network underneath the tunnel. */
    private fun upstreamDnsServers(): List<String> {
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return emptyList()
        val network = manager.activeNetwork ?: return emptyList()
        val props = manager.getLinkProperties(network) ?: return emptyList()
        return props.dnsServers
            .filterIsInstance<Inet4Address>()
            .mapNotNull { it.hostAddress }
            .distinct()
            .take(2)
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
            if (flows.size >= MAX_TCP_FLOWS) evictOldestTcp()
            val relay = TcpRelay(
                tun = TunSink { writePacket(it) },
                first = packet,
                strategy = strategy,
                onClosed = { closed -> flows.remove(closed.key, closed) },
            )
            relay.key = key
            flows[key] = relay
            relay.start(executor)
        } else {
            val flow = flows[key]
            if (flow == null) {
                // Stale connection from before the tunnel started, or one already reaped:
                // refuse it instead of letting the app wait for a timeout.
                if (packet.flags and Packets.TCP_RST == 0) {
                    writePacket(
                        Packets.tcp(
                            src = packet.dst,
                            dst = packet.src,
                            srcPort = packet.dstPort,
                            dstPort = packet.srcPort,
                            seq = packet.ack,
                            ack = 0,
                            flags = Packets.TCP_RST,
                            window = 0,
                            payload = Packets.EMPTY,
                        ),
                    )
                }
            } else {
                flow.onPacket(packet)
            }
        }
    }

    /**
     * QUIC (UDP 443) is relayed like any other UDP flow. Its SNI travels inside the
     * encrypted Initial packet, so a DPI that filters TCP TLS by hostname cannot see it.
     * Dropping QUIC here used to force clients onto TCP, where this provider's filter
     * drops the handshake outright.
     */
    private fun handleUdp(packet: Packets.Ip) {
        // A config can ask to drop QUIC so clients fall back to TCP, where the split is
        // applied. The default relays it, which is what this provider's filter needs.
        if (packet.dstPort == 443 && !strategy.quicRelay) return
        val key = keyOf(packet)
        val existing = udpFlows[key]
        if (existing != null) {
            existing.send(packet.payload)
            return
        }
        if (udpFlows.size >= MAX_UDP_FLOWS) {
            udpFlows.values.minByOrNull { it.lastActive }?.close()
        }
        val relay = UdpRelay(key, packet)
        if (relay.start()) {
            udpFlows[key] = relay
            relay.send(packet.payload)
        }
    }

    private inner class UdpRelay(private val key: String, private val first: Packets.Ip) {
        private var socket: DatagramSocket? = null
        @Volatile var lastActive = SystemClock.elapsedRealtime()
        @Volatile private var closed = false

        /** Opens the socket on the caller thread so the very first datagram is not lost. */
        fun start(): Boolean {
            val created = try {
                DatagramSocket().apply {
                    connect(InetAddress.getByAddress(first.dst), first.dstPort)
                    soTimeout = UDP_TIMEOUT_MS
                }
            } catch (_: Throwable) {
                close()
                return false
            }
            if (closed) {
                runCatching { created.close() }
                return false
            }
            socket = created
            executor.execute { receiveLoop(created) }
            return true
        }

        private fun receiveLoop(socket: DatagramSocket) {
            val buffer = ByteArray(4096)
            var loggedReply = first.dstPort != 443
            while (!closed) {
                try {
                    val response = DatagramPacket(buffer, buffer.size)
                    socket.receive(response)
                    lastActive = SystemClock.elapsedRealtime()
                    if (!loggedReply) {
                        loggedReply = true
                        Log.d(TAG, "QUIC reply ${response.length}B from ${response.address.hostAddress}")
                    }
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

        fun send(payload: ByteArray) {
            lastActive = SystemClock.elapsedRealtime()
            val target = socket ?: return
            runCatching { target.send(DatagramPacket(payload, payload.size)) }
        }

        fun close() {
            if (closed) return
            closed = true
            runCatching { socket?.close() }
            socket = null
            udpFlows.remove(key, this)
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

    private fun evictOldestTcp() {
        val oldest = flows.values.minByOrNull { it.lastActive } ?: return
        flows.remove(oldest.key, oldest)
        oldest.close()
    }

    private fun shutdown() {
        running = false
        handler.removeCallbacks(janitor)
        reader?.interrupt()
        reader = null
        for (flow in flows.values) flow.close()
        flows.clear()
        for (flow in udpFlows.values) flow.close()
        udpFlows.clear()
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
