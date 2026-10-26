package com.thymus.tgwsproxy.bypass

import android.content.Context
import com.thymus.tgwsproxy.data.Settings
import java.io.File
import java.util.UUID

/** Loads the preset list, stores imported configs and remembers the selected one. */
object BypassConfigs {

    private const val DIR = "bypass"
    private const val EXT = ".conf"
    private const val MAX_CONFIG_CHARS = 512_000

    sealed interface ImportResult {
        data class Success(val profile: BypassProfile) : ImportResult
        data class Error(val message: String) : ImportResult
    }

    fun all(context: Context): List<BypassProfile> = BypassPresets.all + custom(context)

    fun selected(context: Context): BypassProfile {
        val id = Settings.bypassConfigId(context)
        return all(context).firstOrNull { it.id == id } ?: BypassPresets.all.first()
    }

    fun import(context: Context, text: String, fileName: String): ImportResult {
        if (text.length > MAX_CONFIG_CHARS) return ImportResult.Error("file is too large")
        val baseName = fileName.substringBeforeLast('.').ifBlank { "Custom" }
        val id = "custom-" + UUID.randomUUID().toString().take(8)
        return when (val parsed = BypassConfigParser.parse(text, baseName, id)) {
            is BypassConfigParser.Result.Error -> ImportResult.Error(parsed.message)
            is BypassConfigParser.Result.Success -> {
                val profile = parsed.profile.copy(id = id, builtIn = false, source = parsed.profile.source)
                val file = File(directory(context), id + EXT)
                val saved = runCatching { file.writeText(serialize(profile)) }.isSuccess
                if (saved) ImportResult.Success(profile) else ImportResult.Error("cannot save config")
            }
        }
    }

    fun delete(context: Context, id: String): Boolean {
        if (BypassPresets.byId(id) != null) return false
        val file = File(directory(context), id + EXT)
        return file.delete()
    }

    /** Serializes a profile back into the native `key=value` format. */
    fun serialize(profile: BypassProfile): String = buildString {
        appendLine("# Thymus bypass config")
        appendLine("name=${profile.name.oneLine()}")
        appendLine("description=${profile.description.oneLine()}")
        val modes = buildList {
            when {
                profile.splitPositions.size > 1 -> add("multisplit")
                profile.splitPositions.size == 1 -> add("split")
            }
            if (profile.oob) add("oob")
        }
        appendLine("desync=${modes.ifEmpty { listOf("none") }.joinToString(",")}")
        if (profile.splitPositions.isNotEmpty()) {
            appendLine("split-pos=${profile.splitPositions.joinToString(",")}")
        }
        appendLine("oob=${if (profile.oob) 1 else 0}")
        appendLine("repeats=${profile.oobRepeats}")
        appendLine("ports=${profile.ports.sorted().joinToString(",")}")
        if (profile.hosts.isNotEmpty()) appendLine("hosts=${profile.hosts.joinToString(",")}")
        appendLine("quic=${if (profile.quicRelay) "relay" else "drop"}")
        for (warning in profile.warnings) appendLine("warning=${warning.oneLine()}")
    }

    private fun custom(context: Context): List<BypassProfile> {
        val files = directory(context).listFiles { file -> file.isFile && file.name.endsWith(EXT) }
            ?: return emptyList()
        return files.mapNotNull { file ->
            val text = runCatching { file.readText() }.getOrNull() ?: return@mapNotNull null
            val id = file.name.removeSuffix(EXT)
            when (val parsed = BypassConfigParser.parse(text, id, id)) {
                is BypassConfigParser.Result.Success ->
                    parsed.profile.copy(id = id, builtIn = false, source = "custom")
                is BypassConfigParser.Result.Error -> null
            }
        }.sortedBy { it.name.lowercase() }
    }

    private fun directory(context: Context): File =
        File(context.applicationContext.filesDir, DIR).apply { mkdirs() }

    private fun String.oneLine(): String = replace('\n', ' ').replace('\r', ' ').trim()
}
