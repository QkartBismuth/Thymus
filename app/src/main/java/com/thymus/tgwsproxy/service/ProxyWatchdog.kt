package com.thymus.tgwsproxy.service

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import com.thymus.tgwsproxy.data.Settings
import com.thymus.tgwsproxy.state.ProxyState

/**
 * Android can kill even a foreground service when memory is tight or when an OEM battery
 * manager decides the app has been idle. START_STICKY brings the service back, but only
 * while the process may still be started; this repeating alarm is a second safety net
 * that checks every 15 minutes and restarts the proxy if the user left it on.
 *
 * The alarm is a wakeup alarm so it also fires while the phone is asleep. It is cheap:
 * the receiver does nothing when the proxy is already running.
 */
object ProxyWatchdog {
    private const val INTERVAL_MS = 15 * 60 * 1000L

    fun schedule(context: Context) {
        val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        manager.setInexactRepeating(
            AlarmManager.ELAPSED_REALTIME_WAKEUP,
            SystemClock.elapsedRealtime() + INTERVAL_MS,
            INTERVAL_MS,
            pendingIntent(context),
        )
    }

    fun cancel(context: Context) {
        val manager = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        manager.cancel(pendingIntent(context))
    }

    private fun pendingIntent(context: Context): PendingIntent =
        PendingIntent.getBroadcast(
            context,
            7,
            Intent(context, WatchdogReceiver::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
}

class WatchdogReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!Settings.isEnabled(context)) return
        if (ProxyState.running.value || ProxyState.starting.value) return
        // Without the battery-optimization exemption Android may reject a foreground
        // service start from the background; the sticky service is the fallback then.
        runCatching { ProxyService.start(context) }
    }
}
