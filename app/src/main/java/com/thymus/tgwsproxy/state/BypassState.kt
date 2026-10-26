package com.thymus.tgwsproxy.state

import kotlinx.coroutines.flow.MutableStateFlow

/** Whether the local VPN that evades DPI is currently established. */
object BypassState {
    val running = MutableStateFlow(false)
    val error = MutableStateFlow<String?>(null)
}
