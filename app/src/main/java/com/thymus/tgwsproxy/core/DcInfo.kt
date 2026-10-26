package com.thymus.tgwsproxy.core

object DcInfo {
    /** Fallback targets for the plain TCP path (Telegram DCs). */
    val DEFAULT_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.50",
        2 to "149.154.167.51",
        3 to "149.154.175.100",
        4 to "149.154.167.91",
        5 to "149.154.171.5",
        203 to "91.105.192.100",
    )

    val TEST_IPS: Map<Int, String> = mapOf(
        1 to "149.154.175.10",
        2 to "149.154.167.40",
        3 to "149.154.175.117",
    )

    /** DCs the proxy tries to reach over WebSocket by default (same as upstream). */
    val DEFAULT_DC_MAP: Map<Int, String> = mapOf(
        2 to "149.154.167.220",
        4 to "149.154.167.220",
    )

    const val WS_PATH = "/apiws"
    const val WS_PATH_TEST = "/apiws_test"

    fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
        val id = if (dc == 203) 2 else dc
        return if (!isMedia) {
            listOf("kws$id.web.telegram.org")
        } else {
            listOf("kws$id-1.web.telegram.org", "kws$id.web.telegram.org")
        }
    }

    fun parseDcMap(raw: String): Map<Int, String> {
        val out = LinkedHashMap<Int, String>()
        for (entry in raw.split(',', ';', ' ', '\n')) {
            val item = entry.trim()
            if (item.isEmpty()) continue
            val parts = item.split(':', '=')
            if (parts.size != 2) continue
            val dc = parts[0].trim().toIntOrNull() ?: continue
            val ip = parts[1].trim()
            if (ip.isEmpty()) continue
            out[dc] = ip
        }
        return out
    }

    fun formatDcMap(map: Map<Int, String>): String =
        map.entries.sortedBy { it.key }.joinToString(",") { "${it.key}:${it.value}" }

    /**
     * The upstream project ships its Cloudflare-proxied fallback domains lightly
     * obfuscated. Same decoding as `_dd()` in proxy/config.py.
     */
    fun decodeCfDomain(encoded: String): String {
        if (!encoded.endsWith(".com")) return encoded
        val body = encoded.dropLast(4)
        val shift = body.count { it.isLetter() }
        val sb = StringBuilder()
        for (ch in body) {
            if (ch.isLetter()) {
                val base = if (ch.code >= 'a'.code) 'a'.code else 'A'.code
                val shifted = (((ch.code - base - shift) % 26) + 26) % 26 + base
                sb.append(shifted.toChar())
            } else {
                sb.append(ch)
            }
        }
        return sb.toString() + ".co.uk"
    }

    private val CF_DOMAINS_ENCODED = listOf(
        "virkgj.com",
        "vmmzovy.com",
        "mkuosckvso.com",
        "zaewayzmplad.com",
        "twdmbzcm.com",
        "awzwsldi.com",
        "clngqrflngqin.com",
        "tjacxbqtj.com",
        "bxaxtxmrw.com",
        "dmohrsgmohcrwb.com",
        "vwbmtmoi.com",
        "khgrre.com",
        "ulihssf.com",
        "tmhqsdqmfpmk.com",
        "xwuwoqbm.com",
        "orgcnunpj.com",
        "zhkuldz.com",
        "zypoljnslxa.com",
        "efabnxaowuzs.com",
        "zaftuzsftqdq.com",
    )

    val DEFAULT_CF_DOMAINS: List<String> = CF_DOMAINS_ENCODED.map { decodeCfDomain(it) }

    fun parseDomainList(raw: String): List<String> =
        raw.split(',', ';', ' ', '\n')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinctBy { it.lowercase() }
}
