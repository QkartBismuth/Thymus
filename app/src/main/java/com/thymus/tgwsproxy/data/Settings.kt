package com.thymus.tgwsproxy.data

import android.content.Context
import com.thymus.tgwsproxy.core.DcInfo
import com.thymus.tgwsproxy.core.ProxyConfig
import com.thymus.tgwsproxy.core.randomBytes
import com.thymus.tgwsproxy.core.toHex

object Settings {
    private const val FILE = "tgws_settings"
    private const val KEY_SECRET = "secret"
    private const val KEY_PORT = "port"
    private const val KEY_DC_MAP = "dc_map"
    private const val KEY_CF_DOMAINS = "cf_domains"
    private const val KEY_CF_ENABLED = "cf_enabled"
    private const val KEY_TCP_ENABLED = "tcp_enabled"
    private const val KEY_AUTOSTART = "autostart"
    private const val KEY_DARK_THEME = "dark_theme"
    private const val KEY_ENABLED = "proxy_enabled"
    private const val KEY_BATTERY_PROMPT = "battery_prompt_shown"

    fun secret(context: Context): String {
        val prefs = prefs(context)
        val existing = prefs.getString(KEY_SECRET, null)
        if (existing != null && existing.length == 32 && existing.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
            return existing
        }
        val generated = randomBytes(16).toHex()
        prefs.edit().putString(KEY_SECRET, generated).apply()
        return generated
    }

    fun regenerateSecret(context: Context): String {
        val generated = randomBytes(16).toHex()
        prefs(context).edit().putString(KEY_SECRET, generated).apply()
        return generated
    }

    fun load(context: Context): ProxyConfig {
        val prefs = prefs(context)
        val dcRaw = prefs.getString(KEY_DC_MAP, null)
        val cfRaw = prefs.getString(KEY_CF_DOMAINS, null)
        return ProxyConfig(
            port = prefs.getInt(KEY_PORT, 1443).coerceIn(1024, 65535),
            secretHex = secret(context),
            dcMap = dcRaw?.let { DcInfo.parseDcMap(it) } ?: DcInfo.DEFAULT_DC_MAP,
            cfDomains = cfRaw?.let { DcInfo.parseDomainList(it) }?.takeIf { it.isNotEmpty() }
                ?: DcInfo.DEFAULT_CF_DOMAINS,
            cfEnabled = prefs.getBoolean(KEY_CF_ENABLED, true),
            tcpEnabled = prefs.getBoolean(KEY_TCP_ENABLED, true),
        )
    }

    fun save(context: Context, config: ProxyConfig) {
        prefs(context).edit()
            .putString(KEY_SECRET, config.secretHex)
            .putInt(KEY_PORT, config.port)
            .putString(KEY_DC_MAP, DcInfo.formatDcMap(config.dcMap))
            .putString(KEY_CF_DOMAINS, config.cfDomains.joinToString(","))
            .putBoolean(KEY_CF_ENABLED, config.cfEnabled)
            .putBoolean(KEY_TCP_ENABLED, config.tcpEnabled)
            .apply()
    }

    /** Persists a fresher Cloudflare domain list downloaded by the engine. */
    fun saveCfDomains(context: Context, domains: List<String>) {
        prefs(context).edit().putString(KEY_CF_DOMAINS, domains.joinToString(",")).apply()
    }

    fun isAutostart(context: Context): Boolean = prefs(context).getBoolean(KEY_AUTOSTART, false)

    fun setAutostart(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTOSTART, value).apply()
    }

    fun isDarkTheme(context: Context): Boolean = prefs(context).getBoolean(KEY_DARK_THEME, false)

    fun setDarkTheme(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_DARK_THEME, value).apply()
    }

    /** True while the user wants the proxy running; survives process death and reboot. */
    fun isEnabled(context: Context): Boolean = prefs(context).getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_ENABLED, value).apply()
    }

    fun isBatteryPromptShown(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BATTERY_PROMPT, false)

    fun setBatteryPromptShown(context: Context) {
        prefs(context).edit().putBoolean(KEY_BATTERY_PROMPT, true).apply()
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
}
