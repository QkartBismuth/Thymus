package com.thymus.tgwsproxy.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.thymus.tgwsproxy.data.Settings

/** Restarts the proxy after a reboot when the user left it switched on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (Settings.isEnabled(context)) ProxyService.start(context)
    }
}
