package com.thymus.tgwsproxy.core

import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException

/** First-successful-candidate probing shared by the engine and the diagnostics. */
internal object WsRace {

    fun run(
        candidates: List<Pair<String, () -> RawWebSocket>>,
        windowMs: Long,
        errors: MutableList<Pair<String, String>>,
    ): Pair<String, RawWebSocket>? {
        if (candidates.isEmpty()) return null
        val lock = Object()
        var finished = false
        var winner: Pair<String, RawWebSocket>? = null
        val latch = CountDownLatch(1)

        for ((label, open) in candidates) {
            Thread({
                try {
                    val ws = open()
                    var adopted = false
                    synchronized(lock) {
                        if (!finished && winner == null) {
                            winner = label to ws
                            adopted = true
                            latch.countDown()
                        }
                    }
                    if (!adopted) ws.closeQuietly()
                } catch (t: Throwable) {
                    synchronized(lock) {
                        if (!finished) errors.add(label to shortError(t))
                    }
                }
            }, "tgws-race").apply {
                isDaemon = true
                start()
            }
        }

        latch.await(windowMs, TimeUnit.MILLISECONDS)
        return synchronized(lock) {
            finished = true
            winner
        }
    }

    fun shortError(t: Throwable): String = when (t) {
        is WsHandshakeException -> if (t.status > 0) "HTTP ${t.status}" else "нет ответа"
        is SocketTimeoutException -> "timeout"
        is UnknownHostException -> "DNS"
        is ConnectException -> "refused"
        is SSLException -> "TLS"
        else -> t.javaClass.simpleName
    }

    /** Turns many per-candidate failures into one readable line: `HTTP 503 ×4, timeout ×2`. */
    fun summarize(errors: List<Pair<String, String>>): String {
        if (errors.isEmpty()) return ""
        return errors.groupingBy { it.second }.eachCount()
            .entries.sortedByDescending { it.value }
            .joinToString(", ") { (reason, count) ->
                if (count > 1) "$reason ×$count" else reason
            }
    }
}
