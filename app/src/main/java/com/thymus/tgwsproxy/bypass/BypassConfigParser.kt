package com.thymus.tgwsproxy.bypass

/**
 * Reads a bypass config from either a zapret `.bat` file or Thymus's own `key=value`
 * format. Only techniques that a userspace socket can actually perform are kept:
 * splitting the ClientHello, the out-of-band byte and port/host filters. Everything that
 * needs raw packets (`fake`, `badseq`, `multidisorder`, custom sequence numbers) is
 * reported in [BypassProfile.warnings] instead of being silently ignored.
 */
object BypassConfigParser {

    sealed interface Result {
        data class Success(val profile: BypassProfile) : Result
        data class Error(val message: String) : Result
    }

    private val SUPPORTED_MODES = setOf("split", "split2", "multisplit", "oob")

    /** Raw-packet techniques that Thymus can approximate with a split plus an OOB byte. */
    private val APPROXIMATED_MODES = setOf(
        "fake", "fakedsplit", "fakeddisorder", "multidisorder", "disorder", "hostfakesplit",
    )

    fun parse(text: String, fallbackName: String, id: String = "custom"): Result {
        val body = text.removePrefix("\uFEFF").trim()
        if (body.isEmpty()) return Result.Error("empty config")
        return if (body.contains("--dpi-desync") || body.contains("winws", ignoreCase = true)) {
            parseZapret(body, fallbackName, id)
        } else {
            parseNative(body, fallbackName, id)
        }
    }

    // ---------------------------------------------------------------- native format

    private fun parseNative(text: String, fallbackName: String, id: String): Result {
        var name = fallbackName
        var description = ""
        var modes = emptyList<String>()
        var positions = emptyList<String>()
        var oob: Boolean? = null
        var repeats = 1
        var ports = emptySet<Int>()
        var hosts = emptyList<String>()
        var quicRelay = true
        val warnings = mutableListOf<String>()

        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";")) continue
            val split = line.indexOf('=')
            if (split <= 0) continue
            val key = line.substring(0, split).trim().lowercase()
            val value = line.substring(split + 1).trim()
            when (key) {
                "name" -> if (value.isNotEmpty()) name = value
                "description" -> description = value
                "desync", "mode", "modes" -> modes = splitList(value)
                "split-pos", "split", "positions" -> positions = splitList(value)
                "oob" -> oob = when (value.lowercase()) {
                    "1", "true", "yes", "on" -> true
                    "0", "false", "no", "off" -> false
                    else -> null
                }
                "repeats" -> repeats = value.toIntOrNull() ?: repeats
                "ports", "port" -> ports = parsePorts(listOf(value))
                "hosts", "hostlist", "domains" -> hosts = splitList(value)
                "quic" -> quicRelay = value.lowercase() !in setOf("drop", "off", "false", "0")
                "warning", "warnings" -> warnings += value.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                else -> warnings += key
            }
        }

        val requested = modes.toSet()
        val explicitlyOff = "none" in requested || "off" in requested
        if (modes.isEmpty() && positions.isEmpty() && oob != true && !explicitlyOff) {
            return Result.Error("no desync modes found")
        }
        val approximated = requested.filter { it in APPROXIMATED_MODES }
        warnings += approximated
        val usesSplit = requested.any { it in SUPPORTED_MODES && it != "oob" } ||
            positions.isNotEmpty() || approximated.isNotEmpty()
        if (positions.isEmpty() && usesSplit) positions = listOf("midsld")
        val effectiveOob = oob ?: ("oob" in requested) || approximated.isNotEmpty()
        if (effectiveOob && positions.isEmpty()) positions = listOf("midsld")
        val unsupported = requested.filter {
            it !in SUPPORTED_MODES && it !in APPROXIMATED_MODES && it !in setOf("none", "off")
        }
        warnings += unsupported

        val profile = BypassProfile(
            id = id,
            name = name,
            description = description.ifEmpty { describe(positions, effectiveOob) },
            splitPositions = positions,
            oob = effectiveOob,
            oobRepeats = repeats,
            ports = ports.ifEmpty { BypassStrategy.DEFAULT_PORTS },
            hosts = hosts,
            quicRelay = quicRelay,
            warnings = warnings.clean(),
            builtIn = false,
            source = "custom",
        )
        return Result.Success(profile)
    }

    // ------------------------------------------------------------------- zapret .bat

    private fun parseZapret(text: String, fallbackName: String, id: String): Result {
        // The .bat files continue long winws.exe commands with a trailing caret.
        val normalized = text.replace("\r\n", "\n").replace(Regex("\\^\\s*\\n"), " ")
        val sections = normalized.split("--new")
        val modes = mutableSetOf<String>()
        val positions = mutableSetOf<String>()
        val ports = mutableSetOf<Int>()
        val hosts = mutableSetOf<String>()
        val warnings = mutableSetOf<String>()
        var repeats = 1
        var sawTcp = false
        var sawUnscopedTcp = false

        for (section in sections) {
            val flags = parseFlags(section)
            val tcp = flags["filter-tcp"]
            if (tcp == null) {
                // Still remember UDP 443 fake rules: they are the QUIC part of the config.
                if (flags["filter-udp"]?.contains("443") == true &&
                    flags["dpi-desync"]?.contains("fake") == true
                ) {
                    warnings += "quic fake"
                }
                continue
            }
            sawTcp = true
            ports += parsePorts(listOf(tcp))
            // A domain-limited section can only be honoured when every TCP section is
            // domain-limited. If one section is global (or uses an unreadable hostlist),
            // the whole config applies to every hostname, which is the safer behaviour.
            val domains = flags["hostlist-domains"]
            if (domains.isNullOrBlank()) {
                sawUnscopedTcp = true
            } else {
                hosts += splitList(domains)
            }
            if (flags.containsKey("hostlist")) warnings += "hostlist"
            if (flags.containsKey("hostlist-exclude")) warnings += "hostlist-exclude"
            if (flags.containsKey("ipset-exclude")) warnings += "ipset-exclude"

            val sectionModes = flags["dpi-desync"].orEmpty()
                .split(',')
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() }
            sectionModes.forEach { mode ->
                when {
                    mode in SUPPORTED_MODES -> modes += mode
                    mode in APPROXIMATED_MODES -> {
                        modes += mode
                        warnings += mode
                    }
                    else -> warnings += mode
                }
            }
            flags["dpi-desync-split-pos"]?.let { raw ->
                splitList(raw).forEach { value ->
                    if (BypassProfile.parseSplitPosition(value) != null) positions += value
                    else warnings += value
                }
            }
            flags["dpi-desync-repeats"]?.toIntOrNull()?.let { repeats = maxOf(repeats, it) }

            for ((key, _) in flags) {
                when {
                    key.startsWith("dpi-desync-fake") -> warnings += "fake"
                    key.startsWith("dpi-desync-split-seqovl") -> warnings += "split-seqovl"
                    key.startsWith("dpi-desync-hostfakesplit") -> warnings += "hostfakesplit"
                    key == "dpi-desync-fooling" -> warnings += "fooling"
                    key == "dpi-desync-cutoff" -> warnings += "cutoff"
                    key == "dpi-desync-any-protocol" -> warnings += "any-protocol"
                    key == "ip-id" -> warnings += "ip-id"
                    key == "filter-l7" -> warnings += "filter-l7"
                    key.startsWith("wf-") -> Unit
                    key.startsWith("dpi-desync") && key !in setOf(
                        "dpi-desync", "dpi-desync-split-pos", "dpi-desync-repeats",
                    ) -> warnings += key.removePrefix("dpi-desync-")
                }
            }
        }

        if (!sawTcp) return Result.Error("no TCP section found")
        // fake/fakedsplit/hostfakesplit/multidisorder need raw packets, but the split
        // they perform can still be approximated from a userspace socket, so they are
        // accepted and reported instead of rejecting the whole config.
        if (modes.none { it in SUPPORTED_MODES || it in APPROXIMATED_MODES }) {
            return Result.Error("no supported desync (split/multisplit/oob) found")
        }

        val splitPositions = positions.toList().ifEmpty { listOf("midsld") }

        val profile = BypassProfile(
            id = id,
            name = fallbackName,
            description = describe(splitPositions, oob = true),
            splitPositions = splitPositions,
            oob = true,
            oobRepeats = repeats.coerceIn(1, BypassProfile.MAX_OOB_REPEATS),
            ports = ports.ifEmpty { BypassStrategy.DEFAULT_PORTS },
            hosts = if (sawUnscopedTcp) emptyList() else hosts.toList(),
            quicRelay = true,
            warnings = warnings.filter { it.isNotBlank() }.distinct(),
            builtIn = false,
            source = "zapret",
        )
        return Result.Success(profile)
    }

    /** Extracts `--name=value` flags from one `--new` section. */
    private fun parseFlags(section: String): Map<String, String> {
        val result = linkedMapOf<String, String>()
        val regex = Regex("--([a-z0-9-]+)(?:=(\"[^\"]*\"|'[^']*'|[^\\s^]+))?")
        for (match in regex.findAll(section)) {
            val key = match.groupValues[1]
            val value = match.groupValues[2].trim().trim('"', '\'')
            if (value.isEmpty()) {
                result.putIfAbsent(key, "")
            } else {
                val previous = result[key]
                result[key] = if (previous.isNullOrEmpty()) value else "$previous,$value"
            }
        }
        return result
    }

    // ---------------------------------------------------------------------- helpers

    private fun describe(positions: List<String>, oob: Boolean): String {
        val split = when {
            positions.isEmpty() -> "no split"
            else -> positions.joinToString(" + ")
        }
        return if (oob) "OOB + $split" else split
    }

    private fun splitList(value: String): List<String> =
        value.split(',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }

    private fun parsePorts(values: List<String>): Set<Int> {
        val result = mutableSetOf<Int>()
        for (value in values) {
            for (part in value.split(',')) {
                val text = part.trim()
                if (text.isEmpty()) continue
                val dash = text.indexOf('-')
                if (dash > 0) {
                    val from = text.substring(0, dash).trim().toIntOrNull()
                    val to = text.substring(dash + 1).trim().toIntOrNull()
                    if (from != null && to != null && from <= to) {
                        for (port in from..to) {
                            if (port in 1..65535) result += port
                        }
                    }
                } else {
                    text.toIntOrNull()?.takeIf { it in 1..65535 }?.let { result += it }
                }
            }
        }
        return result
    }

    private fun List<String>.clean(): List<String> =
        map { it.trim().lowercase() }.filter { it.isNotEmpty() }.distinct()
}
