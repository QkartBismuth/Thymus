package com.thymus.tgwsproxy.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.thymus.tgwsproxy.MainActivity
import com.thymus.tgwsproxy.R
import com.thymus.tgwsproxy.core.ProxyEngine
import com.thymus.tgwsproxy.data.Settings
import com.thymus.tgwsproxy.state.ProxyLog
import com.thymus.tgwsproxy.state.ProxyState

class ProxyService : Service() {

    companion object {
        // New channel with minimal importance: no sound, no status-bar icon, hidden on the
        // lock screen. Combined with not holding POST_NOTIFICATIONS, Android 13+ shows no
        // notification at all while the foreground service keeps running.
        private const val CHANNEL_ID = "proxy_service_v2"
        private const val OLD_CHANNEL_ID = "proxy"
        private const val NOTIFICATION_ID = 1443
        const val ACTION_START = "com.thymus.tgwsproxy.action.START"
        const val ACTION_STOP = "com.thymus.tgwsproxy.action.STOP"
        const val ACTION_RESTART = "com.thymus.tgwsproxy.action.RESTART"

        fun start(context: Context) {
            val intent = Intent(context, ProxyService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            // stopService() is safe even if the service is not running, and it does not
            // impose the startForeground() deadline that startForegroundService() does.
            context.stopService(Intent(context, ProxyService::class.java))
        }

        /** Applies new settings: the engine is torn down and re-created with a fresh config. */
        fun restart(context: Context) {
            val intent = Intent(context, ProxyService::class.java).setAction(ACTION_RESTART)
            ContextCompat.startForegroundService(context, intent)
        }
    }

    private val handler = Handler(Looper.getMainLooper())
    private var engine: ProxyEngine? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var lastNotificationAt = 0L
    private var port = 1443

    /** The warning is a "recently seen" indicator: hide it once Telegram stops retrying. */
    private val clearSecretMismatch = Runnable { ProxyState.secretMismatch.value = false }

    private val ticker = object : Runnable {
        override fun run() {
            val current = engine ?: return
            ProxyState.connections.value = current.activeConnections.get()
            ProxyState.bytesUp.value = current.bytesUp.get()
            ProxyState.bytesDown.value = current.bytesDown.get()
            ProxyState.wsConnections.value = current.wsConnections.get()
            ProxyState.cfConnections.value = current.cfConnections.get()
            ProxyState.tcpConnections.value = current.tcpConnections.get()

            val now = SystemClock.elapsedRealtime()
            if (now - lastNotificationAt > 3000) {
                lastNotificationAt = now
                if (notificationsVisible()) {
                    runCatching {
                        notificationManager().notify(
                            NOTIFICATION_ID,
                            buildNotification(port, current.activeConnections.get()),
                        )
                    }
                }
            }
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                Settings.setEnabled(this, false)
                ProxyWatchdog.cancel(this)
                stopProxy()
                stopSelf()
                return START_NOT_STICKY
            }

            ACTION_RESTART -> {
                teardownEngine()
                startProxy()
                return START_STICKY
            }

            else -> {
                Settings.setEnabled(this, true)
                startProxy()
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startProxy() {
        if (engine != null) return
        val config = Settings.load(this)
        port = config.port

        ProxyState.starting.value = true
        ProxyState.error.value = null
        startForeground(NOTIFICATION_ID, buildNotification(config.port, 0))

        val newEngine = ProxyEngine(
            config = config,
            log = { message -> ProxyLog.add(message) },
            onCfDomains = { domains -> Settings.saveCfDomains(this, domains) },
            onSecretMismatch = {
                handler.post {
                    ProxyState.secretMismatch.value = true
                    handler.removeCallbacks(clearSecretMismatch)
                    handler.postDelayed(clearSecretMismatch, 15_000)
                }
            },
        )
        if (!newEngine.start()) {
            ProxyState.starting.value = false
            ProxyState.error.value = getString(R.string.status_error, "127.0.0.1:${config.port}")
            ProxyLog.add("Не удалось запустить прокси на порту ${config.port}")
            stopSelf()
            return
        }

        engine = newEngine
        ProxyState.running.value = true
        ProxyState.starting.value = false
        acquireWakeLock()
        ProxyWatchdog.schedule(this)
        ProxyLog.add("Прокси запущен, ссылка: tg://proxy?server=127.0.0.1&port=${config.port}&secret=dd${config.secretHex}")
        handler.post(ticker)
    }

    private fun teardownEngine() {
        handler.removeCallbacks(ticker)
        val current = engine
        engine = null
        if (current != null) {
            runCatching { current.stop() }
        }
        ProxyState.reset()
    }

    private fun stopProxy() {
        val wasRunning = engine != null
        teardownEngine()
        if (wasRunning) ProxyLog.add("Прокси остановлен")
        releaseWakeLock()
        ProxyState.reset()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun acquireWakeLock() {
        if (wakeLock != null) return
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "tgws:proxy").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }

    private fun createChannel() {
        val manager = notificationManager()
        // The old channel was created with IMPORTANCE_LOW and can no longer be changed
        // for existing installs, so it is replaced by a fresh, quieter one.
        runCatching { manager.deleteNotificationChannel(OLD_CHANNEL_ID) }
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel),
            NotificationManager.IMPORTANCE_MIN,
        ).apply {
            setShowBadge(false)
            enableVibration(false)
            setSound(null, null)
            lockscreenVisibility = Notification.VISIBILITY_SECRET
            description = getString(R.string.notif_channel)
        }
        manager.createNotificationChannel(channel)
    }

    private fun notificationManager(): NotificationManager =
        getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    /** False when the app does not hold POST_NOTIFICATIONS (Android 13+), i.e. always. */
    private fun notificationsVisible(): Boolean =
        NotificationManagerCompat.from(this).areNotificationsEnabled()

    private fun buildNotification(port: Int, connections: Int): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_proxy)
            .setContentTitle(getString(R.string.notif_title))
            .setContentText(getString(R.string.notif_text, port, connections))
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_SECRET)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(0, getString(R.string.notif_stop), stopIntent)
            .build()
    }
}
