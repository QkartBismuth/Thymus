package com.thymus.tgwsproxy.core

data class ProxyConfig(
    val host: String = "127.0.0.1",
    val port: Int = 1443,
    val secretHex: String,
    val dcMap: Map<Int, String> = DcInfo.DEFAULT_DC_MAP,
    val cfDomains: List<String> = DcInfo.DEFAULT_CF_DOMAINS,
    val cfEnabled: Boolean = true,
    val tcpEnabled: Boolean = true,
    val forceTestDc: Boolean = false,
    /** Probe the routes once in the background after start (disabled in tests). */
    val warmup: Boolean = true,
) {
    val secret: ByteArray by lazy { secretHex.hexToBytes() }
}
