package com.thymus.tgwsproxy.state

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Rolling in-app log, also mirrored to logcat. */
object ProxyLog {
    private const val TAG = "TgWsProxy"
    private const val LIMIT = 300

    private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)
    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines.asStateFlow()

    fun add(message: String) {
        Log.i(TAG, message)
        val stamp = synchronized(timeFormat) { timeFormat.format(Date()) }
        _lines.update { current -> (current + "$stamp  $message").takeLast(LIMIT) }
    }

    fun clear() {
        _lines.value = emptyList()
    }
}

object ProxyState {
    val running = MutableStateFlow(false)
    val starting = MutableStateFlow(false)
    val error = MutableStateFlow<String?>(null)
    val secretMismatch = MutableStateFlow(false)
    val connections = MutableStateFlow(0)
    val bytesUp = MutableStateFlow(0L)
    val bytesDown = MutableStateFlow(0L)
    val wsConnections = MutableStateFlow(0L)
    val cfConnections = MutableStateFlow(0L)
    val tcpConnections = MutableStateFlow(0L)

    fun reset() {
        running.value = false
        starting.value = false
        secretMismatch.value = false
        connections.value = 0
        bytesUp.value = 0L
        bytesDown.value = 0L
        wsConnections.value = 0L
        cfConnections.value = 0L
        tcpConnections.value = 0L
    }
}
