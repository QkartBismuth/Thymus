package com.thymus.tgwsproxy.bypass

/**
 * One way of splitting the first TLS ClientHello.
 *
 * [Keyword] cuts inside the word the filter looks for (zapret's `midsld` idea), [Middle]
 * cuts in the middle of the whole hostname, [HostStart] cuts right before the hostname and
 * [Offset] cuts at a fixed byte offset inside the TLS record body.
 */
sealed interface SplitPosition {
    data object Keyword : SplitPosition
    data object Middle : SplitPosition
    data object HostStart : SplitPosition
    data class Offset(val bytes: Int) : SplitPosition
}

/** Everything the TCP relay needs to know about the selected config. */
data class BypassStrategy(
    val splitPositions: List<SplitPosition> = emptyList(),
    val oob: Boolean = false,
    val oobRepeats: Int = 1,
    val ports: Set<Int> = DEFAULT_PORTS,
    val hosts: List<String> = emptyList(),
    val quicRelay: Boolean = true,
) {
    val active: Boolean get() = splitPositions.isNotEmpty() || oob

    fun appliesToPort(port: Int): Boolean = port in ports

    /** An empty host list means "every hostname". Entries match a domain and its subdomains. */
    fun appliesToHost(host: String?): Boolean {
        if (hosts.isEmpty()) return true
        val name = host?.lowercase()?.trim('.') ?: return false
        return hosts.any { pattern ->
            val clean = pattern.lowercase().trim('.')
            when {
                clean.startsWith("*.") -> name.endsWith(clean.substring(1))
                else -> name == clean || name.endsWith(".$clean")
            }
        }
    }

    companion object {
        val DEFAULT_PORTS = setOf(80, 443, 2053, 2083, 2087, 2096, 8443)
    }
}

/**
 * A selectable bypass config: either a built-in preset that mirrors a zapret `.bat`, or a
 * config the user imported. [warnings] lists techniques that the original config used but
 * that need root, so the UI can say what was skipped.
 */
data class BypassProfile(
    val id: String,
    val name: String,
    val description: String,
    val splitPositions: List<String>,
    val oob: Boolean,
    val oobRepeats: Int = 1,
    val ports: Set<Int> = BypassStrategy.DEFAULT_PORTS,
    val hosts: List<String> = emptyList(),
    val quicRelay: Boolean = true,
    val warnings: List<String> = emptyList(),
    val builtIn: Boolean = false,
    val source: String = "preset",
) {
    fun toStrategy(): BypassStrategy = BypassStrategy(
        splitPositions = splitPositions.mapNotNull(::parseSplitPosition),
        oob = oob,
        oobRepeats = oobRepeats.coerceIn(1, MAX_OOB_REPEATS),
        ports = ports.ifEmpty { BypassStrategy.DEFAULT_PORTS },
        hosts = hosts.map { it.lowercase().trim('.') }.filter { it.isNotEmpty() },
        quicRelay = quicRelay,
    )

    companion object {
        const val MAX_OOB_REPEATS = 4

        fun parseSplitPosition(value: String): SplitPosition? {
            val text = value.trim().lowercase()
            return when {
                text.isEmpty() -> null
                text in setOf("midsld", "keyword", "sni") -> SplitPosition.Keyword
                text in setOf("middle", "midhost", "mid") -> SplitPosition.Middle
                text in setOf("host", "hoststart") -> SplitPosition.HostStart
                else -> text.toIntOrNull()?.let { SplitPosition.Offset(it) }
            }
        }
    }
}

/** Built-in strategies, named after the zapret configs they are adapted from. */
object BypassPresets {
    const val DEFAULT_ID = "general"

    val all: List<BypassProfile> = listOf(
        BypassProfile(
            id = DEFAULT_ID,
            name = "General",
            description = "OOB + midsld",
            splitPositions = listOf("midsld"),
            oob = true,
            builtIn = true,
        ),
        BypassProfile(
            id = "alt",
            name = "General (ALT)",
            description = "multisplit 1 + middle + midsld, OOB",
            splitPositions = listOf("1", "middle", "midsld"),
            oob = true,
            warnings = listOf("fake", "fakedsplit"),
            builtIn = true,
        ),
        BypassProfile(
            id = "alt2",
            name = "General (ALT2)",
            description = "multisplit 1 + midsld, OOB",
            splitPositions = listOf("1", "midsld"),
            oob = true,
            warnings = listOf("split-seqovl"),
            builtIn = true,
        ),
        BypassProfile(
            id = "fake-tls-auto",
            name = "General (FAKE TLS AUTO)",
            description = "OOB + midsld",
            splitPositions = listOf("midsld"),
            oob = true,
            oobRepeats = 2,
            warnings = listOf("fake", "badseq", "multidisorder"),
            builtIn = true,
        ),
        BypassProfile(
            id = "simple-fake",
            name = "General (SIMPLE FAKE)",
            description = "split 1 + OOB",
            splitPositions = listOf("1"),
            oob = true,
            warnings = listOf("fake"),
            builtIn = true,
        ),
        BypassProfile(
            id = "exp",
            name = "General (EXP)",
            description = "multisplit 1 + midsld, OOB",
            splitPositions = listOf("1", "midsld"),
            oob = true,
            warnings = listOf("fake", "split-seqovl"),
            builtIn = true,
        ),
        BypassProfile(
            id = "split-only",
            name = "Split only",
            description = "2 TLS records, no OOB",
            splitPositions = listOf("midsld"),
            oob = false,
            builtIn = true,
        ),
        BypassProfile(
            id = "oob-middle",
            name = "OOB (single split)",
            description = "OOB + middle",
            splitPositions = listOf("middle"),
            oob = true,
            builtIn = true,
        ),
        BypassProfile(
            id = "passthrough",
            name = "Pass-through",
            description = "no desync, tunnel only",
            splitPositions = emptyList(),
            oob = false,
            builtIn = true,
        ),
    )

    fun byId(id: String): BypassProfile? = all.firstOrNull { it.id == id }
}
