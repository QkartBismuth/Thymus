package com.thymus.tgwsproxy.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.thymus.tgwsproxy.R
import com.thymus.tgwsproxy.bypass.BypassProfile

/**
 * Full-screen settings: proxy credentials, routing, connection details and system
 * toggles. The main screen only keeps the three actions, so this is where everything
 * that is configured once lives.
 */
@Composable
fun SettingsScreen(
    modifier: Modifier = Modifier,
    darkTheme: Boolean,
    onThemeChange: (Boolean) -> Unit,
    bypassEnabled: Boolean,
    bypassRunning: Boolean,
    bypassConfigs: List<BypassProfile>,
    bypassConfigId: String,
    onBypassChange: (Boolean) -> Unit,
    onBypassConfigSelect: (String) -> Unit,
    onBypassConfigDelete: (String) -> Unit,
    onBypassConfigImport: () -> Unit,
    autoSelecting: Boolean,
    autoDone: Int,
    autoTotal: Int,
    onBypassAutoSelect: () -> Unit,
    port: String,
    onPortChange: (String) -> Unit,
    secret: String,
    onSecretChange: (String) -> Unit,
    dcMap: String,
    onDcMapChange: (String) -> Unit,
    domains: String,
    onDomainsChange: (String) -> Unit,
    cfEnabled: Boolean,
    onCfEnabledChange: (Boolean) -> Unit,
    tcpEnabled: Boolean,
    onTcpEnabledChange: (Boolean) -> Unit,
    autostart: Boolean,
    onAutostartChange: (Boolean) -> Unit,
    currentPort: Int,
    currentSecret: String,
    logLines: List<String>,
    onCopy: (String) -> Unit,
    onRegenerate: () -> Unit,
    onOpenTelegram: () -> Unit,
    onOpenBattery: () -> Unit,
    onDiagnose: () -> Unit,
    onSave: () -> Unit,
    onBack: () -> Unit,
) {
    var logExpanded by rememberSaveable { mutableStateOf(false) }
    var showConfigPicker by rememberSaveable { mutableStateOf(false) }
    val selectedConfig = bypassConfigs.firstOrNull { it.id == bypassConfigId }
        ?: bypassConfigs.firstOrNull()

    LazyColumn(
        modifier = modifier,
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp, 8.dp, 16.dp, 32.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(42.dp)
                        .shadow(
                            elevation = 6.dp,
                            shape = CircleShape,
                            ambientColor = Palette.Pine.copy(alpha = 0.12f),
                            spotColor = Palette.Pine.copy(alpha = 0.14f),
                        )
                        .clip(CircleShape)
                        .background(Palette.Milk)
                        .clickable(onClick = onBack),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = "←",
                        fontSize = 19.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = Palette.Ink,
                    )
                }
                Spacer(Modifier.width(14.dp))
                Column {
                    Text(
                        text = stringResourceSafe(R.string.section_settings),
                        fontSize = 21.sp,
                        fontWeight = FontWeight.Bold,
                        color = Palette.Ink,
                    )
                }
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_proxy))
                SettingsField(
                    value = port,
                    onValueChange = { onPortChange(it.filter(Char::isDigit).take(5)) },
                    label = stringResourceSafe(R.string.setting_port),
                    keyboardType = KeyboardType.Number,
                )
                Spacer(Modifier.height(10.dp))
                SettingsField(
                    value = secret,
                    onValueChange = {
                        onSecretChange(it.lowercase().filter { c -> c.isDigit() || c in 'a'..'f' }.take(32))
                    },
                    label = stringResourceSafe(R.string.setting_secret),
                    mono = true,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    TextButton(onClick = onRegenerate, contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp)) {
                        Text(
                            text = stringResourceSafe(R.string.action_regenerate),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.Ink,
                        )
                    }
                    TextButton(onClick = { onCopy(secret) }, contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp)) {
                        Text(
                            text = stringResourceSafe(R.string.action_copy_secret),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.Ink,
                        )
                    }
                }
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_routes))
                SettingsField(
                    value = dcMap,
                    onValueChange = onDcMapChange,
                    label = stringResourceSafe(R.string.setting_dc_map),
                    mono = true,
                    small = true,
                    minLines = 2,
                    maxLines = 4,
                )
                Spacer(Modifier.height(10.dp))
                SettingsField(
                    value = domains,
                    onValueChange = onDomainsChange,
                    label = stringResourceSafe(R.string.setting_domains),
                    mono = true,
                    small = true,
                    minLines = 3,
                    maxLines = 6,
                )
                Spacer(Modifier.height(6.dp))
                ToggleRow(
                    title = stringResourceSafe(R.string.setting_cf_fallback),
                    checked = cfEnabled,
                    onChange = onCfEnabledChange,
                )
                ToggleRow(
                    title = stringResourceSafe(R.string.setting_tcp_fallback),
                    checked = tcpEnabled,
                    onChange = onTcpEnabledChange,
                )
            }
        }

        item {
            Button(
                onClick = onSave,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(20.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = Palette.Pine,
                    contentColor = Palette.OnPine,
                ),
                elevation = ButtonDefaults.buttonElevation(
                    defaultElevation = 0.dp,
                    pressedElevation = 2.dp,
                ),
            ) {
                Text(
                    text = stringResourceSafe(R.string.action_save),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_connect))
                Text(
                    text = proxyLink(currentPort, currentSecret),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = Palette.PineMuted,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.height(12.dp))
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Button(
                        onClick = onOpenTelegram,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Palette.Champagne,
                            contentColor = Palette.Pine,
                        ),
                        elevation = ButtonDefaults.buttonElevation(defaultElevation = 0.dp),
                    ) {
                        Text(
                            text = stringResourceSafe(R.string.action_open_telegram),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                    OutlinedButton(
                        onClick = { onCopy(proxyLink(currentPort, currentSecret)) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(48.dp),
                        shape = RoundedCornerShape(16.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            containerColor = Palette.Milk,
                            contentColor = Palette.Ink,
                        ),
                    ) {
                        Text(
                            text = stringResourceSafe(R.string.action_copy_link),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                Text(
                    text = stringResourceSafe(R.string.connect_hint),
                    fontSize = 12.sp,
                    color = Palette.PineMuted,
                )
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = Palette.OutlineSoft)
                Spacer(Modifier.height(10.dp))
                InfoRow(stringResourceSafe(R.string.manual_server), "127.0.0.1")
                InfoRow(stringResourceSafe(R.string.manual_port), currentPort.toString())
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = stringResourceSafe(R.string.manual_secret),
                        fontSize = 12.sp,
                        color = Palette.PineMuted,
                        modifier = Modifier.width(96.dp),
                    )
                    Text(
                        text = "dd$currentSecret",
                        fontSize = 11.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Palette.Ink,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    TextButton(
                        onClick = { onCopy("dd$currentSecret") },
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
                    ) {
                        Text(
                            text = stringResourceSafe(R.string.action_copy_secret),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.Ink,
                        )
                    }
                }
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_system))
                ToggleRow(
                    title = stringResourceSafe(R.string.setting_autostart),
                    checked = autostart,
                    onChange = onAutostartChange,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onOpenBattery,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = Palette.Milk,
                        contentColor = Palette.Ink,
                    ),
                ) {
                    Text(
                        text = stringResourceSafe(R.string.action_battery),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResourceSafe(R.string.battery_hint),
                    fontSize = 11.sp,
                    lineHeight = 16.sp,
                    color = Palette.PineMuted,
                )
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_bypass))
                ToggleRow(
                    title = stringResourceSafe(R.string.bypass_title),
                    checked = bypassEnabled,
                    onChange = onBypassChange,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    text = stringResourceSafe(
                        when {
                            bypassEnabled && bypassRunning -> R.string.bypass_hint_on
                            bypassEnabled -> R.string.bypass_hint_pending
                            else -> R.string.bypass_hint_off
                        },
                    ),
                    fontSize = 11.sp,
                    lineHeight = 16.sp,
                    color = Palette.PineMuted,
                )
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = Palette.OutlineSoft)
                Spacer(Modifier.height(10.dp))
                Text(
                    text = stringResourceSafe(R.string.bypass_config),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = Palette.Ink,
                )
                Spacer(Modifier.height(6.dp))
                if (selectedConfig != null) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(14.dp))
                            .background(Palette.LavenderLight)
                            .clickable { showConfigPicker = true }
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                text = selectedConfig.name,
                                fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = Palette.Ink,
                            )
                            Text(
                                text = selectedConfig.description,
                                fontSize = 11.sp,
                                lineHeight = 15.sp,
                                color = Palette.PineMuted,
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = stringResourceSafe(R.string.bypass_config_change),
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.Ink,
                        )
                    }
                    if (selectedConfig.warnings.isNotEmpty()) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text = stringResourceSafe(
                                R.string.bypass_config_notes,
                                selectedConfig.warnings.joinToString(", "),
                            ),
                            fontSize = 10.sp,
                            lineHeight = 14.sp,
                            color = Palette.PineMuted,
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = onBypassAutoSelect,
                    enabled = !autoSelecting,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Palette.Pine,
                        contentColor = Palette.OnPine,
                        disabledContainerColor = Palette.Pine,
                        disabledContentColor = Palette.OnPine,
                    ),
                ) {
                    Text(
                        text = if (autoSelecting) {
                            stringResourceSafe(R.string.bypass_auto_running, autoDone, autoTotal)
                        } else {
                            stringResourceSafe(R.string.bypass_auto)
                        },
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResourceSafe(R.string.bypass_auto_hint),
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = Palette.PineMuted,
                )
                Spacer(Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onBypassConfigImport,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        containerColor = Palette.Milk,
                        contentColor = Palette.Ink,
                    ),
                ) {
                    Text(
                        text = stringResourceSafe(R.string.bypass_config_import),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResourceSafe(R.string.bypass_config_import_hint),
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = Palette.PineMuted,
                )
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_theme))
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    ThemeChip(
                        label = stringResourceSafe(R.string.theme_light),
                        selected = !darkTheme,
                        onClick = { onThemeChange(false) },
                        modifier = Modifier.weight(1f),
                    )
                    ThemeChip(
                        label = stringResourceSafe(R.string.theme_dark),
                        selected = darkTheme,
                        onClick = { onThemeChange(true) },
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }

        item {
            SectionCard {
                SectionTitle(stringResourceSafe(R.string.section_log))
                Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    TextButton(
                        onClick = onDiagnose,
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
                    ) {
                        Text(
                            text = stringResourceSafe(R.string.action_diagnose),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.Ink,
                        )
                    }
                    TextButton(
                        onClick = { onCopy(logLines.joinToString("\n")) },
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
                    ) {
                        Text(
                            text = stringResourceSafe(R.string.action_copy_log),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.Ink,
                        )
                    }
                }
                val visible = if (logExpanded) logLines.takeLast(80) else logLines.takeLast(5)
                if (visible.isEmpty()) {
                    Text(
                        text = stringResourceSafe(R.string.log_empty),
                        fontSize = 12.sp,
                        color = Palette.PineMuted,
                    )
                } else {
                    Text(
                        text = visible.joinToString("\n"),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        lineHeight = 16.sp,
                        color = Palette.Ink.copy(alpha = 0.78f),
                    )
                }
                if (logLines.size > 5) {
                    TextButton(
                        onClick = { logExpanded = !logExpanded },
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
                    ) {
                        Text(
                            text = stringResourceSafe(
                                if (logExpanded) R.string.action_collapse_log else R.string.action_expand_log,
                            ),
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = Palette.PineMuted,
                        )
                    }
                }
            }
        }
    }

    if (showConfigPicker) {
        BypassConfigDialog(
            configs = bypassConfigs,
            selectedId = selectedConfig?.id,
            onSelect = {
                onBypassConfigSelect(it)
                showConfigPicker = false
            },
            onDelete = onBypassConfigDelete,
            onImport = {
                showConfigPicker = false
                onBypassConfigImport()
            },
            onDismiss = { showConfigPicker = false },
        )
    }
}

/** Picker that mirrors zapret's config list and lists imported configs below it. */
@Composable
private fun BypassConfigDialog(
    configs: List<BypassProfile>,
    selectedId: String?,
    onSelect: (String) -> Unit,
    onDelete: (String) -> Unit,
    onImport: () -> Unit,
    onDismiss: () -> Unit,
) {
    val presets = configs.filter { it.builtIn }
    val custom = configs.filterNot { it.builtIn }
    AlertDialog(
        onDismissRequest = onDismiss,
        shape = RoundedCornerShape(24.dp),
        containerColor = Palette.Milk,
        titleContentColor = Palette.Ink,
        textContentColor = Palette.PineMuted,
        title = {
            Text(
                text = stringResourceSafe(R.string.bypass_config_picker_title),
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            LazyColumn(
                modifier = Modifier.heightIn(max = 420.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                item {
                    ConfigGroupTitle(stringResourceSafe(R.string.bypass_config_presets))
                }
                items(presets, key = { it.id }) { profile ->
                    ConfigOption(
                        profile = profile,
                        selected = profile.id == selectedId,
                        onClick = { onSelect(profile.id) },
                    )
                }
                item {
                    Spacer(Modifier.height(6.dp))
                    ConfigGroupTitle(stringResourceSafe(R.string.bypass_config_custom))
                }
                if (custom.isEmpty()) {
                    item {
                        Text(
                            text = stringResourceSafe(R.string.bypass_config_empty),
                            fontSize = 11.sp,
                            color = Palette.PineMuted,
                        )
                    }
                }
                items(custom, key = { it.id }) { profile ->
                    ConfigOption(
                        profile = profile,
                        selected = profile.id == selectedId,
                        onClick = { onSelect(profile.id) },
                        onDelete = { onDelete(profile.id) },
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(
                    text = stringResourceSafe(R.string.action_close),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Palette.Ink,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onImport) {
                Text(
                    text = stringResourceSafe(R.string.bypass_config_import),
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Palette.Pine,
                )
            }
        },
    )
}

@Composable
private fun ConfigGroupTitle(text: String) {
    Text(
        text = text,
        fontSize = 10.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.6.sp,
        color = Palette.PineMuted,
    )
}

@Composable
private fun ConfigOption(
    profile: BypassProfile,
    selected: Boolean,
    onClick: () -> Unit,
    onDelete: (() -> Unit)? = null,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) Palette.LavenderLight else Color.Transparent)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = profile.name,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = Palette.Ink,
                )
                Text(
                    text = profile.description,
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    color = Palette.PineMuted,
                )
            }
            if (selected) {
                Text(
                    text = "✓",
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    color = Palette.Pine,
                )
            }
        }
        if (profile.warnings.isNotEmpty()) {
            Spacer(Modifier.height(2.dp))
            Text(
                text = stringResourceSafe(
                    R.string.bypass_config_notes,
                    profile.warnings.joinToString(", "),
                ),
                fontSize = 10.sp,
                lineHeight = 14.sp,
                color = Palette.PineMuted.copy(alpha = 0.85f),
            )
        }
        if (onDelete != null) {
            Spacer(Modifier.height(2.dp))
            Text(
                text = stringResourceSafe(R.string.bypass_config_delete),
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                color = Palette.Pine,
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .clickable(onClick = onDelete)
                    .padding(horizontal = 4.dp, vertical = 2.dp),
            )
        }
    }
}

@Composable
private fun SettingsField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    keyboardType: KeyboardType = KeyboardType.Text,
    mono: Boolean = false,
    small: Boolean = false,
    minLines: Int = 1,
    maxLines: Int = 1,
) {
    val baseStyle = if (small) MaterialTheme.typography.bodySmall else MaterialTheme.typography.bodyMedium
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = maxLines == 1,
        minLines = minLines,
        maxLines = maxLines,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        textStyle = if (mono) baseStyle.copy(fontFamily = FontFamily.Monospace) else baseStyle,
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Palette.Ink,
            unfocusedBorderColor = Palette.Ink.copy(alpha = 0.18f),
            focusedLabelColor = Palette.Ink,
            unfocusedLabelColor = Palette.PineMuted,
            cursorColor = Palette.Ink,
            focusedTextColor = Palette.Ink,
            unfocusedTextColor = Palette.Ink,
            focusedContainerColor = Color.Transparent,
            unfocusedContainerColor = Color.Transparent,
        ),
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(
            text = label,
            fontSize = 12.sp,
            color = Palette.PineMuted,
            modifier = Modifier.width(96.dp),
        )
        Text(
            text = value,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = Palette.Ink,
        )
    }
}

@Composable
private fun ToggleRow(title: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onChange(!checked) },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = title,
            fontSize = 13.sp,
            fontWeight = FontWeight.Medium,
            color = Palette.Ink,
            modifier = Modifier.weight(1f),
        )
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = Palette.OnPine,
                checkedTrackColor = Palette.Pine,
                checkedBorderColor = Palette.Pine,
                uncheckedThumbColor = Palette.OnPine,
                uncheckedTrackColor = Palette.Ink.copy(alpha = 0.12f),
                uncheckedBorderColor = Palette.Ink.copy(alpha = 0.30f),
            ),
        )
    }
}

/** Pill used to pick the light or the dark palette. */
@Composable
private fun ThemeChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier
            .height(44.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(if (selected) Palette.Pine else Palette.LavenderLight)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (selected) Palette.OnPine else Palette.Ink,
        )
    }
}
