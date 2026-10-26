package com.thymus.tgwsproxy.ui

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.PowerManager
import android.provider.OpenableColumns
import android.provider.Settings as AndroidSettings
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.thymus.tgwsproxy.R
import com.thymus.tgwsproxy.bypass.BypassConfigs
import com.thymus.tgwsproxy.bypass.BypassPresets
import com.thymus.tgwsproxy.bypass.BypassProbe
import com.thymus.tgwsproxy.core.DcInfo
import com.thymus.tgwsproxy.core.ProxyConfig
import com.thymus.tgwsproxy.core.ProxyDiagnostics
import com.thymus.tgwsproxy.data.Settings
import com.thymus.tgwsproxy.service.BypassService
import com.thymus.tgwsproxy.service.ProxyService
import com.thymus.tgwsproxy.state.BypassState
import com.thymus.tgwsproxy.state.ProxyLog
import com.thymus.tgwsproxy.state.ProxyState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale

@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    val running by ProxyState.running.collectAsStateWithLifecycle()
    val starting by ProxyState.starting.collectAsStateWithLifecycle()
    val error by ProxyState.error.collectAsStateWithLifecycle()
    val secretMismatch by ProxyState.secretMismatch.collectAsStateWithLifecycle()
    val bytesUp by ProxyState.bytesUp.collectAsStateWithLifecycle()
    val bytesDown by ProxyState.bytesDown.collectAsStateWithLifecycle()
    val logLines by ProxyLog.lines.collectAsStateWithLifecycle()

    var config by remember { mutableStateOf(Settings.load(context)) }

    var portText by remember { mutableStateOf(config.port.toString()) }
    var secretText by remember { mutableStateOf(config.secretHex) }
    var dcText by remember { mutableStateOf(DcInfo.formatDcMap(config.dcMap)) }
    var domainsText by remember { mutableStateOf(config.cfDomains.joinToString(",")) }
    var cfEnabled by remember { mutableStateOf(config.cfEnabled) }
    var tcpEnabled by remember { mutableStateOf(config.tcpEnabled) }
    var autostart by remember { mutableStateOf(Settings.isAutostart(context)) }

    var showSettings by rememberSaveable { mutableStateOf(false) }
    var showBatteryPrompt by rememberSaveable { mutableStateOf(false) }

    val bypassRunning by BypassState.running.collectAsStateWithLifecycle()
    var bypassEnabled by remember { mutableStateOf(Settings.isBypassEnabled(context)) }
    var bypassConfigs by remember { mutableStateOf(BypassConfigs.all(context)) }
    var bypassConfigId by remember { mutableStateOf(Settings.bypassConfigId(context)) }
    var autoSelecting by remember { mutableStateOf(false) }
    var autoDone by remember { mutableStateOf(0) }
    var autoTotal by remember { mutableStateOf(0) }

    fun refreshConfigs() {
        bypassConfigs = BypassConfigs.all(context)
    }

    fun selectConfig(id: String, notify: Boolean = true) {
        Settings.setBypassConfigId(context, id)
        bypassConfigId = id
        // Existing connections keep their strategy; only new ones use the new config.
        if (bypassEnabled) BypassService.reload(context)
        if (!notify) return
        val name = bypassConfigs.firstOrNull { it.id == id }?.name ?: id
        scope.launch { snackbar.showSnackbar(context.getString(R.string.bypass_config_applied, name)) }
    }

    fun deleteConfig(id: String) {
        if (!BypassConfigs.delete(context, id)) return
        refreshConfigs()
        if (bypassConfigId == id) selectConfig(BypassPresets.DEFAULT_ID, notify = false)
        scope.launch { snackbar.showSnackbar(context.getString(R.string.bypass_config_deleted)) }
    }

    /**
     * Sends a real ClientHello through every config and keeps the one the servers answer
     * to. Runs off the main thread; the VPN (if on) is bypassed for the probe sockets.
     */
    fun autoSelectConfig() {
        if (autoSelecting) return
        val profiles = bypassConfigs
        if (profiles.isEmpty()) return
        autoSelecting = true
        autoDone = 0
        autoTotal = profiles.size
        scope.launch {
            val scores = withContext(Dispatchers.IO) {
                BypassProbe.evaluate(profiles) { done, total ->
                    scope.launch {
                        autoDone = done
                        autoTotal = total
                    }
                }
            }
            autoSelecting = false
            val best = BypassProbe.rank(scores)
            if (best == null) {
                snackbar.showSnackbar(context.getString(R.string.bypass_auto_failed))
            } else {
                selectConfig(best.profile.id, notify = false)
                snackbar.showSnackbar(
                    context.getString(
                        R.string.bypass_auto_selected,
                        best.profile.name,
                        best.ok,
                        best.total,
                    ),
                )
            }
        }
    }

    val bypassPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            Settings.setBypassEnabled(context, true)
            bypassEnabled = true
            BypassService.start(context)
        } else {
            Settings.setBypassEnabled(context, false)
            bypassEnabled = false
            scope.launch { snackbar.showSnackbar(context.getString(R.string.bypass_permission_denied)) }
        }
    }

    val importConfig = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val text = readConfig(context, uri)
                    val name = displayName(context, uri) ?: "config.conf"
                    BypassConfigs.import(context, text, name)
                }.getOrElse { BypassConfigs.ImportResult.Error(it.message ?: "read error") }
            }
            when (result) {
                is BypassConfigs.ImportResult.Success -> {
                    refreshConfigs()
                    selectConfig(result.profile.id, notify = false)
                    snackbar.showSnackbar(
                        context.getString(R.string.bypass_config_imported, result.profile.name),
                    )
                }
                is BypassConfigs.ImportResult.Error ->
                    snackbar.showSnackbar(
                        context.getString(R.string.bypass_config_import_failed, result.message),
                    )
            }
        }
    }

    fun setBypass(enabled: Boolean) {
        if (!enabled) {
            Settings.setBypassEnabled(context, false)
            bypassEnabled = false
            BypassService.stop(context)
            return
        }
        val consent = VpnService.prepare(context)
        if (consent != null) {
            bypassPermission.launch(consent)
        } else {
            Settings.setBypassEnabled(context, true)
            bypassEnabled = true
            BypassService.start(context)
        }
    }

    // Ask once, on the first launch, for the exemption that keeps Android from killing the
    // proxy while the screen is off. The same action stays available in Settings.
    LaunchedEffect(Unit) {
        if (!Settings.isBatteryPromptShown(context) && !isBatteryOptimizationIgnored(context)) {
            showBatteryPrompt = true
        }
    }

    // System back from settings should return to the main screen, not leave the app.
    BackHandler(enabled = showSettings) { showSettings = false }

    LaunchedEffect(Unit) {
        if (Settings.isAutostart(context) && !ProxyState.running.value && !ProxyState.starting.value) {
            ProxyService.start(context)
        }
    }

    LaunchedEffect(Unit) {
        if (Settings.isBypassEnabled(context) &&
            !BypassState.running.value &&
            VpnService.prepare(context) == null
        ) {
            BypassService.start(context)
        }
    }

    LaunchedEffect(bypassRunning) {
        bypassEnabled = Settings.isBypassEnabled(context)
    }

    LaunchedEffect(error) {
        error?.let { snackbar.showSnackbar(it) }
    }

    val bypassError by BypassState.error.collectAsStateWithLifecycle()
    LaunchedEffect(bypassError) {
        bypassError?.let {
            snackbar.showSnackbar(it)
            bypassEnabled = Settings.isBypassEnabled(context)
            BypassState.error.value = null
        }
    }

    fun copy(text: String, label: String) {
        clipboard.setText(AnnotatedString(text))
        scope.launch { snackbar.showSnackbar(label) }
    }

    fun applySettings(): Boolean {
        val previous = config
        val port = portText.trim().toIntOrNull()
        val secret = secretText.trim().lowercase(Locale.US)
        val dcMap = DcInfo.parseDcMap(dcText)
        val valid = port != null && port in 1024..65535 &&
            secret.length == 32 && secret.all { Character.digit(it, 16) >= 0 }
        if (!valid) {
            scope.launch { snackbar.showSnackbar(context.getString(R.string.settings_invalid)) }
            return false
        }
        val updated = ProxyConfig(
            port = port!!,
            secretHex = secret,
            dcMap = dcMap,
            cfDomains = DcInfo.parseDomainList(domainsText),
            cfEnabled = cfEnabled,
            tcpEnabled = tcpEnabled,
        )
        Settings.save(context, updated)
        config = updated
        val credentialsChanged = updated.port != previous.port || updated.secretHex != previous.secretHex
        if (running || starting) ProxyService.restart(context)
        scope.launch {
            snackbar.showSnackbar(
                context.getString(
                    if (credentialsChanged) R.string.settings_readd else R.string.settings_saved,
                ),
            )
        }
        return true
    }

    Scaffold(
        containerColor = Color.Transparent,
        snackbarHost = { SnackbarHost(snackbar) },
    ) { innerPadding ->
        if (showSettings) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(Palette.Lavender),
            ) {
                SettingsScreen(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding),
                    darkTheme = ThemeState.isDark,
                    onThemeChange = { applyTheme(context, it) },
                    bypassEnabled = bypassEnabled,
                    bypassRunning = bypassRunning,
                    bypassConfigs = bypassConfigs,
                    bypassConfigId = bypassConfigId,
                    onBypassChange = { setBypass(it) },
                    onBypassConfigSelect = { selectConfig(it) },
                    onBypassConfigDelete = { deleteConfig(it) },
                    onBypassConfigImport = { importConfig.launch(arrayOf("*/*")) },
                    autoSelecting = autoSelecting,
                    autoDone = autoDone,
                    autoTotal = autoTotal,
                    onBypassAutoSelect = { autoSelectConfig() },
                    port = portText,
                    onPortChange = { portText = it },
                    secret = secretText,
                    onSecretChange = { secretText = it },
                    dcMap = dcText,
                    onDcMapChange = { dcText = it },
                    domains = domainsText,
                    onDomainsChange = { domainsText = it },
                    cfEnabled = cfEnabled,
                    onCfEnabledChange = { cfEnabled = it },
                    tcpEnabled = tcpEnabled,
                    onTcpEnabledChange = { tcpEnabled = it },
                    autostart = autostart,
                    onAutostartChange = {
                        autostart = it
                        Settings.setAutostart(context, it)
                    },
                    currentPort = config.port,
                    currentSecret = config.secretHex,
                    logLines = logLines,
                    onCopy = { text -> copy(text, context.getString(R.string.copied)) },
                    onRegenerate = { secretText = Settings.regenerateSecret(context) },
                    onOpenTelegram = { openTelegram(context, config.port, config.secretHex) },
                    onOpenBattery = { openBatterySettings(context) },
                    onDiagnose = {
                        val cfg = config
                        scope.launch(Dispatchers.IO) {
                            ProxyDiagnostics.run(cfg) { ProxyLog.add(it) }
                        }
                    },
                    onSave = { if (applySettings()) showSettings = false },
                    onBack = { showSettings = false },
                )
            }
        } else {
            HomeContent(
                modifier = Modifier.fillMaxSize(),
                contentPadding = innerPadding,
                running = running,
                starting = starting,
                secretMismatch = secretMismatch,
                bytesUp = bytesUp,
                bytesDown = bytesDown,
                onToggle = {
                    if (running || starting) {
                        ProxyService.stop(context)
                    } else {
                        ProxyService.start(context)
                    }
                },
                onConnect = {
                    if (running) {
                        openTelegram(context, config.port, config.secretHex)
                    } else {
                        scope.launch { snackbar.showSnackbar(context.getString(R.string.connect_first)) }
                    }
                },
                onSettings = { showSettings = true },
                onOpenTelegramApp = {
                    if (!openTelegramApp(context)) {
                        scope.launch {
                            snackbar.showSnackbar(context.getString(R.string.telegram_not_found))
                        }
                    }
                },
            )
        }
    }

    if (showBatteryPrompt) {
        BatteryPrompt(
            onAllow = {
                showBatteryPrompt = false
                Settings.setBatteryPromptShown(context)
                openBatterySettings(context)
            },
            onDismiss = {
                showBatteryPrompt = false
                Settings.setBatteryPromptShown(context)
            },
        )
    }
}

/**
 * The main screen follows the reference mockup: a full-bleed botanical background, a gear
 * in the corner, one large power button with a compact Telegram pill under it, and a pale
 * card with the traffic counters at the bottom.
 */
@Composable
private fun HomeContent(
    modifier: Modifier,
    contentPadding: PaddingValues,
    running: Boolean,
    starting: Boolean,
    secretMismatch: Boolean,
    bytesUp: Long,
    bytesDown: Long,
    onToggle: () -> Unit,
    onConnect: () -> Unit,
    onSettings: () -> Unit,
    onOpenTelegramApp: () -> Unit,
) {
    Box(modifier) {
        Image(
            painter = painterResource(if (ThemeState.isDark) R.drawable.back_dark else R.drawable.back),
            contentDescription = null,
            modifier = Modifier.fillMaxSize(),
            contentScale = ContentScale.Crop,
        )

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(contentPadding)
                .padding(horizontal = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 10.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                GearButton(onClick = onSettings)
            }

            Spacer(Modifier.weight(1f))

            PowerButton(
                running = running,
                starting = starting,
                onClick = onToggle,
            )

            Spacer(Modifier.height(18.dp))

            ConnectButton(onClick = onConnect)

            if (secretMismatch) {
                Spacer(Modifier.height(18.dp))
                MismatchNotice(onOpenTelegram = onOpenTelegramApp)
            }

            Spacer(Modifier.weight(1f))

            TrafficCard(bytesDown = bytesDown, bytesUp = bytesUp)

            Spacer(Modifier.height(26.dp))
        }
    }
}

@Composable
private fun GearButton(onClick: () -> Unit) {
    val shape = RoundedCornerShape(15.dp)
    Box(
        modifier = Modifier
            .size(44.dp)
            .shadow(
                elevation = 8.dp,
                shape = shape,
                ambientColor = Palette.Pine.copy(alpha = 0.22f),
                spotColor = Palette.Pine.copy(alpha = 0.24f),
            )
            .clip(shape)
            .background(Palette.Pine)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_settings),
            contentDescription = stringResourceSafe(R.string.action_settings),
            modifier = Modifier.size(26.dp),
        )
    }
}

@Composable
private fun PowerButton(running: Boolean, starting: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(26.dp)
    val container = if (running) Palette.ChampagneLight else Palette.Pine
    val content = if (running) Palette.Pine else Palette.OnPine
    val label = when {
        starting -> stringResourceSafe(R.string.status_starting)
        running -> stringResourceSafe(R.string.action_stop)
        else -> stringResourceSafe(R.string.action_start)
    }
    Box(
        modifier = Modifier
            .fillMaxWidth(0.62f)
            .height(88.dp)
            .shadow(
                elevation = 14.dp,
                shape = shape,
                ambientColor = Palette.Pine.copy(alpha = 0.22f),
                spotColor = Palette.Pine.copy(alpha = 0.26f),
            )
            .clip(shape)
            .background(container)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontSize = 32.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = (-0.4).sp,
            color = content,
            maxLines = 1,
        )
    }
}

@Composable
private fun ConnectButton(onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .height(48.dp)
            .shadow(
                elevation = 8.dp,
                shape = RoundedCornerShape(50),
                ambientColor = Palette.Pine.copy(alpha = 0.22f),
                spotColor = Palette.Pine.copy(alpha = 0.24f),
            )
            .clip(RoundedCornerShape(50))
            .background(Palette.Pine)
            .clickable(onClick = onClick)
            .padding(start = 8.dp, end = 20.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Image(
            painter = painterResource(R.drawable.ic_telegram),
            contentDescription = null,
            modifier = Modifier.size(32.dp),
        )
        Text(
            text = stringResourceSafe(R.string.action_connect_telegram),
            fontSize = 17.sp,
            fontWeight = FontWeight.Bold,
            color = Palette.OnPine,
        )
    }
}

@Composable
private fun MismatchNotice(onOpenTelegram: () -> Unit) {
    val shape = RoundedCornerShape(20.dp)
    Column(
        modifier = Modifier
            .fillMaxWidth(0.88f)
            .shadow(
                elevation = 8.dp,
                shape = shape,
                ambientColor = Palette.Pine.copy(alpha = 0.16f),
                spotColor = Palette.Pine.copy(alpha = 0.18f),
            )
            .clip(shape)
            .background(Palette.ChampagneLight)
            .padding(horizontal = 16.dp, vertical = 14.dp),
    ) {
        Text(
            text = stringResourceSafe(R.string.secret_mismatch_title),
            fontSize = 13.sp,
            fontWeight = FontWeight.Bold,
            color = Palette.Pine,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResourceSafe(R.string.secret_mismatch_body),
            fontSize = 11.sp,
            lineHeight = 15.sp,
            color = Palette.Pine.copy(alpha = 0.82f),
        )
        TextButton(
            onClick = onOpenTelegram,
            contentPadding = androidx.compose.foundation.layout.PaddingValues(0.dp),
        ) {
            Text(
                text = stringResourceSafe(R.string.action_open_telegram_app),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
                color = Palette.Pine,
            )
        }
    }
}

@Composable
private fun BatteryPrompt(onAllow: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(24.dp),
        containerColor = Palette.Milk,
        titleContentColor = Palette.Ink,
        textContentColor = Palette.PineMuted,
        title = {
            Text(
                text = stringResourceSafe(R.string.battery_prompt_title),
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Text(
                text = stringResourceSafe(R.string.battery_prompt_body),
                fontSize = 13.sp,
                lineHeight = 19.sp,
            )
        },
        confirmButton = {
            TextButton(onClick = onAllow) {
                Text(
                    text = stringResourceSafe(R.string.action_allow),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Palette.Ink,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = stringResourceSafe(R.string.action_later),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = Palette.PineMuted,
                )
            }
        },
    )
}

@Composable
private fun TrafficCard(bytesDown: Long, bytesUp: Long) {
    val shape = RoundedCornerShape(28.dp)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(96.dp)
            .shadow(
                elevation = 12.dp,
                shape = shape,
                ambientColor = Palette.Pine.copy(alpha = 0.18f),
                spotColor = Palette.Pine.copy(alpha = 0.20f),
            )
            .clip(shape)
            .background(Palette.LavenderPaper)
            .padding(horizontal = 18.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        TrafficValue(arrow = "↓", value = humanBytes(bytesDown), modifier = Modifier.weight(1f))
        TrafficValue(arrow = "↑", value = humanBytes(bytesUp), modifier = Modifier.weight(1f))
    }
}

@Composable
private fun TrafficValue(arrow: String, value: String, modifier: Modifier) {
    Row(
        modifier = modifier,
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = arrow,
            fontSize = 20.sp,
            fontWeight = FontWeight.Medium,
            color = Palette.OnCard.copy(alpha = 0.85f),
        )
        Spacer(Modifier.width(7.dp))
        Text(
            text = value,
            fontSize = 21.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = (-0.2).sp,
            color = Palette.OnCard,
            maxLines = 1,
        )
    }
}

@Composable
internal fun stringResourceSafe(id: Int, vararg args: Any): String =
    androidx.compose.ui.res.stringResource(id, *args)

internal fun proxyLink(port: Int, secretHex: String): String =
    "tg://proxy?server=127.0.0.1&port=$port&secret=dd$secretHex"

internal fun openTelegram(context: Context, port: Int, secretHex: String) {
    val secret = "dd$secretHex"
    val tg = Uri.parse("tg://proxy?server=127.0.0.1&port=$port&secret=$secret")
    val web = Uri.parse("https://t.me/proxy?server=127.0.0.1&port=$port&secret=$secret")
    try {
        context.startActivity(Intent(Intent.ACTION_VIEW, tg))
    } catch (_: Throwable) {
        runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, web)) }
    }
}

/** Switches the theme for the running session and remembers the choice. */
internal fun applyTheme(context: Context, dark: Boolean) {
    ThemeState.set(if (dark) ThemeMode.DARK else ThemeMode.LIGHT)
    Settings.setDarkTheme(context, dark)
}

/**
 * Opens Telegram itself (whatever screen the user left it on) instead of adding a proxy.
 * Returns false when no Telegram client could be launched.
 */
internal fun openTelegramApp(context: Context): Boolean {
    val pm = context.packageManager
    for (pkg in TELEGRAM_PACKAGES) {
        val launch = pm.getLaunchIntentForPackage(pkg) ?: continue
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED)
        if (runCatching { context.startActivity(launch) }.isSuccess) return true
    }
    // Package visibility may still hide the client, but the tg:// scheme filter usually resolves.
    val scheme = Intent(Intent.ACTION_VIEW, Uri.parse("tg://settings"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    return runCatching { context.startActivity(scheme) }.isSuccess
}

private val TELEGRAM_PACKAGES = listOf(
    "org.telegram.messenger",
    "org.telegram.messenger.web",
    "org.telegram.plus",
    "org.thunderdog.challegram",
)

/** Human-readable file name of a content:// URI picked in the import dialog. */
private fun displayName(context: Context, uri: Uri): String? = runCatching {
    context.contentResolver
        .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
}.getOrNull()

/** Reads an imported config with a hard cap, so picking a huge file cannot exhaust memory. */
private fun readConfig(context: Context, uri: Uri): String {
    val limit = 512 * 1024
    val input = context.contentResolver.openInputStream(uri) ?: error("empty file")
    return input.use { stream ->
        val out = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val read = stream.read(buffer)
            if (read < 0) break
            if (out.size() + read > limit) error("file is too large")
            out.write(buffer, 0, read)
        }
        out.toByteArray().toString(Charsets.UTF_8)
    }
}

internal fun isBatteryOptimizationIgnored(context: Context): Boolean {
    val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    return power.isIgnoringBatteryOptimizations(context.packageName)
}

internal fun openBatterySettings(context: Context) {
    val request = if (!isBatteryOptimizationIgnored(context)) {
        Intent(
            AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            Uri.parse("package:${context.packageName}"),
        )
    } else {
        Intent(AndroidSettings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
    }
    runCatching { context.startActivity(request) }
}

internal fun humanBytes(value: Long): String {
    if (value < 1024) return "$value B"
    val units = arrayOf("KB", "MB", "GB", "TB")
    var size = value.toDouble() / 1024
    var unit = 0
    while (size >= 1024 && unit < units.lastIndex) {
        size /= 1024
        unit++
    }
    return String.format(Locale.US, "%.2f %s", size, units[unit])
}
