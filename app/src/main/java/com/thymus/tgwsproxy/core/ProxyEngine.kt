package com.thymus.tgwsproxy.core

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.HttpsURLConnection

/**
 * Local MTProto proxy: accepts connections from the Telegram app, reads the obfuscated
 * handshake to learn the destination DC, then re-encrypts the stream and relays it over
 * a WebSocket (or plain TCP as a fallback).
 */
class ProxyEngine(
    private val config: ProxyConfig,
    private val log: (String) -> Unit,
    /** Called when a fresher Cloudflare domain list was downloaded, so it can be persisted. */
    private val onCfDomains: ((List<String>) -> Unit)? = null,
    /** Called (throttled) when Telegram connects with a secret that does not match. */
    private val onSecretMismatch: (() -> Unit)? = null,
) {
    private val executor = Executors.newCachedThreadPool { r ->
        Thread(r, "tgws-client").apply { isDaemon = true }
    }
    private val clients: MutableSet<Socket> =
        Collections.newSetFromMap(ConcurrentHashMap<Socket, Boolean>())
    private val tunnels: MutableSet<Tunnel> =
        Collections.newSetFromMap(ConcurrentHashMap<Tunnel, Boolean>())

    @Volatile
    private var lastSecretMismatchAt = 0L

    @Volatile
    private var running = false
    private var serverSocket: ServerSocket? = null
    private var extraServerSocket: ServerSocket? = null
    private var acceptThread: Thread? = null

    /** Actual listening port; useful when [ProxyConfig.port] is 0 (tests). */
    @Volatile
    var boundPort: Int = 0
        private set

    val activeConnections = AtomicInteger()
    val totalConnections = AtomicLong()
    val bytesUp = AtomicLong()
    val bytesDown = AtomicLong()
    val wsConnections = AtomicLong()
    val cfConnections = AtomicLong()
    val tcpConnections = AtomicLong()

    private enum class Route { DIRECT, CF, TCP }

    /** Remembers the route that worked last time, per DC, so reconnects skip failed routes. */
    private val preferredRoutes = ConcurrentHashMap<Int, Route>()

    /**
     * An already upgraded TLS+WS connection to a DC that has not sent its relay init
     * yet. Telegram opens new MTProto connections in bursts (and after every network
     * change), and each one used to pay 0.5–1.8 s for the TLS and HTTP upgrade. Keeping
     * one spare tunnel per DC removes that from the critical path.
     */
    private class Pooled(
        val dc: Int,
        val media: Boolean,
        val route: Route,
        val tunnel: Tunnel,
        val at: Long,
    )

    private val poolLock = Any()
    private val pool = ArrayList<Pooled>()

    /** Last refill attempt per `dc:media`, so a burst of connections does not spawn ten. */
    private val refillAt = HashMap<String, Long>()

    /** Set while a connection is using a pooled tunnel, so a dead one can be detected. */
    private val pooledUse = ThreadLocal<Boolean>()

    @Volatile
    private var pooledDisabledUntil = 0L

    /** Spare tunnels currently held; used by tests to wait for a refill. */
    val pooledCount: Int get() = synchronized(poolLock) { pool.size }

    @Volatile
    private var workingCfDomain: String? = null

    /** Domains that answered with 503/timeout, with the time they may be retried. */
    private val cfDeadUntil = ConcurrentHashMap<String, Long>()

    @Volatile
    private var cfDomains: List<String> = config.cfDomains

    fun start(): Boolean {
        if (running) return true
        val socket = ServerSocket()
        socket.reuseAddress = true
        return try {
            socket.bind(InetSocketAddress(config.host, config.port), 64)
            serverSocket = socket
            boundPort = socket.localPort
            running = true
            acceptThread = Thread({ acceptLoop(socket) }, "tgws-accept").apply {
                isDaemon = true
                start()
            }
            // Some clients resolve "localhost" to ::1; accepting both loopbacks costs
            // nothing and removes a whole class of "failed to connect".
            if (config.host == "127.0.0.1" && config.port != 0) {
                runCatching {
                    val v6 = ServerSocket().apply { reuseAddress = true }
                    v6.bind(InetSocketAddress(InetAddress.getByName("::1"), boundPort), 16)
                    extraServerSocket = v6
                    Thread({ acceptLoop(v6) }, "tgws-accept6").apply {
                        isDaemon = true
                        start()
                    }
                }
            }
            log("Слушаю ${config.host}:${config.port}")
            if (config.cfDomains == DcInfo.DEFAULT_CF_DOMAINS) refreshCfDomains()
            startPoolCleaner()
            if (config.warmup) warmup()
            true
        } catch (t: Throwable) {
            runCatching { socket.close() }
            log("Не удалось занять порт ${config.port}: ${t.message}")
            false
        }
    }

    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        runCatching { extraServerSocket?.close() }
        serverSocket = null
        extraServerSocket = null
        val pooled = synchronized(poolLock) {
            val copy = pool.toList()
            pool.clear()
            refillAt.clear()
            copy
        }
        for (entry in pooled) runCatching { entry.tunnel.close() }
        for (tunnel in tunnels.toList()) runCatching { tunnel.close() }
        tunnels.clear()
        for (client in clients.toList()) runCatching { client.close() }
        clients.clear()
        executor.shutdownNow()
    }

    private fun acceptLoop(server: ServerSocket) {
        while (running) {
            val client = try {
                server.accept()
            } catch (t: Throwable) {
                if (running) log("accept: ${t.message}")
                break
            }
            totalConnections.incrementAndGet()
            clients.add(client)
            try {
                executor.execute { handle(client) }
            } catch (_: Throwable) {
                clients.remove(client)
                runCatching { client.close() }
            }
        }
    }

    private fun handle(client: Socket) {
        var tunnel: Tunnel? = null
        var counted = false
        pooledUse.remove()
        try {
            client.tcpNoDelay = true
            client.soTimeout = 10_000
            val cin = BufferedInputStream(client.getInputStream(), 32 * 1024)
            val cout = BufferedOutputStream(client.getOutputStream(), 32 * 1024)

            val packet = readHandshake(cin) ?: return
            val handshake = MtProto.parseHandshake(packet, config.secret)
            if (handshake == null) {
                // Telegram retries a proxy with the wrong secret in a tight loop, so
                // this fires dozens of times per second: throttle the log and tell the
                // UI once, instead of filling the whole log with one line.
                val now = System.currentTimeMillis()
                if (now - lastSecretMismatchAt > 3000) {
                    lastSecretMismatchAt = now
                    log("Неверный handshake: в Telegram осталась запись со старым секретом — удалите её")
                    onSecretMismatch?.invoke()
                }
                return
            }

            var dc = handshake.dc
            var isTest = config.forceTestDc
            if (dc >= 10000) {
                dc -= 10000
                isTest = true
            }
            if (dc <= 0) return

            val media = if (handshake.isMedia) " media" else ""
            val relayInit = MtProto.buildRelayInit(
                handshake.protoTag,
                if (handshake.isMedia) -dc else dc,
            )
            val ctx = MtProto.buildCrypto(handshake, config.secret, relayInit)
            val splitter = MsgSplitter(handshake.protoInt)

            client.soTimeout = 0
            activeConnections.incrementAndGet()
            counted = true

            tunnel = if (isTest) openTcp(dc, true) else openRelay(dc, handshake.isMedia)
            if (tunnel == null) {
                log("DC$dc$media: нет доступного маршрута")
                return
            }
            tunnels.add(tunnel)

            tunnel.send(relayInit)
            log("DC$dc$media: соединение установлено")

            val fromPool = pooledUse.get() == true
            val downBefore = bytesDown.get()
            val establishedAt = System.currentTimeMillis()
            bridge(client, cin, cout, tunnel, ctx, splitter)

            // A pooled tunnel that dies immediately and delivered nothing was most likely
            // already closed by the server while it sat idle. Stop reusing them for a while
            // instead of letting every new connection fail the same way.
            if (fromPool && System.currentTimeMillis() - establishedAt < 1500 &&
                bytesDown.get() == downBefore
            ) {
                markPoolBad()
            }
        } catch (t: Throwable) {
            if (running) log("соединение: ${t.javaClass.simpleName}: ${t.message}")
        } finally {
            pooledUse.remove()
            if (counted) activeConnections.decrementAndGet()
            tunnel?.let {
                tunnels.remove(it)
                runCatching { it.close() }
            }
            clients.remove(client)
            runCatching { client.close() }
        }
    }

    private fun openRelay(dc: Int, isMedia: Boolean): Tunnel? {
        val mapDc = if (dc == 203) 2 else dc
        val canWs = config.dcMap.containsKey(mapDc)

        // Ready TLS+WS tunnel from the spare pool: no routing decision, no handshake.
        if (canWs || config.cfEnabled) {
            val ready = takePooled(dc, isMedia, preferredRoutes[mapDc])
            if (ready != null) {
                pooledUse.set(true)
                countRoute(ready.first)
                scheduleRefill(dc, isMedia, ready.first)
                return ready.second
            }
        }

        // First contact with this DC: start the direct and the Cloudflare path at the
        // same time and take whichever connects first. Telegram only waits a couple of
        // seconds for a new proxy connection, so probing a blocked direct route before
        // even trying Cloudflare made the first connection look dead (and showed up as
        // a multi-second "ping" in Telegram).
        if (preferredRoutes[mapDc] == null && canWs && config.cfEnabled) {
            val raced = raceRoutes(
                listOf(
                    Route.DIRECT to { directWs(dc, isMedia) },
                    Route.CF to { cfWs(dc, isMedia) },
                ),
                6500,
            )
            if (raced != null) return adopt(dc, mapDc, isMedia, raced.first, raced.second)

            val tcp = if (config.tcpEnabled) openTcp(dc, false) else null
            if (tcp != null) return adopt(dc, mapDc, isMedia, Route.TCP, tcp)
            return null
        }

        val order = ArrayList<Route>(3)
        fun add(route: Route) {
            if (!order.contains(route)) order.add(route)
        }
        when (preferredRoutes[mapDc]) {
            Route.CF -> if (config.cfEnabled) add(Route.CF)
            Route.TCP -> if (config.tcpEnabled) add(Route.TCP)
            Route.DIRECT, null -> Unit
        }
        if (canWs) add(Route.DIRECT)
        if (config.cfEnabled) add(Route.CF)
        if (config.tcpEnabled) add(Route.TCP)

        for (route in order) {
            val tunnel = when (route) {
                Route.DIRECT -> directWs(dc, isMedia)
                Route.CF -> cfWs(dc, isMedia)
                Route.TCP -> openTcp(dc, false)
            }
            if (tunnel != null) {
                countRoute(route)
                val previous = preferredRoutes.put(mapDc, route)
                if (previous != null && previous != route) {
                    log("DC$dc: маршрут ${route.name}")
                }
                scheduleRefill(dc, isMedia, route)
                return tunnel
            }
        }
        return null
    }

    /** Counts the connection for the chosen route. */
    private fun countRoute(route: Route) {
        when (route) {
            Route.DIRECT -> wsConnections.incrementAndGet()
            Route.CF -> cfConnections.incrementAndGet()
            Route.TCP -> tcpConnections.incrementAndGet()
        }
    }

    /** Counts the connection for the chosen route and remembers it for this DC. */
    private fun adopt(dc: Int, mapDc: Int, isMedia: Boolean, route: Route, tunnel: Tunnel): Tunnel {
        countRoute(route)
        preferredRoutes[mapDc] = route
        log("DC$dc: маршрут ${route.name}")
        scheduleRefill(dc, isMedia, route)
        return tunnel
    }

    /**
     * Returns a spare tunnel for this stream and removes it from the pool, or null.
     * Expired and already-closed entries are discarded (and closed) on the way.
     */
    private fun takePooled(dc: Int, isMedia: Boolean, preferred: Route?): Pair<Route, Tunnel>? {
        if (System.currentTimeMillis() < pooledDisabledUntil) return null
        val now = System.currentTimeMillis()
        var chosen: Pooled? = null
        val dropped = ArrayList<Pooled>()
        synchronized(poolLock) {
            val iterator = pool.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                if (now - entry.at > POOL_TTL_MS || !entry.tunnel.isAlive) {
                    iterator.remove()
                    dropped.add(entry)
                }
            }
            val candidates = pool.filter { it.dc == dc && it.media == isMedia }
            chosen = candidates.firstOrNull { it.route == preferred } ?: candidates.firstOrNull()
            if (chosen != null) pool.remove(chosen)
        }
        for (entry in dropped) runCatching { entry.tunnel.close() }
        val ready = chosen ?: return null
        log("DC$dc${if (isMedia) " media" else ""}: готовое соединение ${ready.route.name} (${now - ready.at} мс)")
        return ready.route to ready.tunnel
    }

    /** Puts a freshly opened, unused tunnel into the pool (or closes it when there is no room). */
    private fun offerPool(dc: Int, isMedia: Boolean, route: Route, tunnel: Tunnel) {
        if (route == Route.TCP || !running || System.currentTimeMillis() < pooledDisabledUntil) {
            runCatching { tunnel.close() }
            return
        }
        val kept = synchronized(poolLock) {
            val room = pool.size < MAX_POOL && pool.none { it.dc == dc && it.media == isMedia }
            if (running && room) {
                pool.add(Pooled(dc, isMedia, route, tunnel, System.currentTimeMillis()))
                true
            } else {
                false
            }
        }
        if (!kept) runCatching { tunnel.close() }
    }

    /**
     * Opens one spare tunnel in the background after a connection used up the pool entry,
     * so the next Telegram reconnect is instant too. Never blocks the caller.
     */
    private fun scheduleRefill(dc: Int, isMedia: Boolean, route: Route) {
        if (route == Route.TCP || !running) return
        val now = System.currentTimeMillis()
        if (now < pooledDisabledUntil) return
        val key = "$dc:$isMedia"
        val allowed = synchronized(poolLock) {
            if (pool.any { it.dc == dc && it.media == isMedia }) {
                false
            } else if (now - (refillAt[key] ?: 0L) < REFILL_INTERVAL_MS) {
                false
            } else {
                refillAt[key] = now
                true
            }
        }
        if (!allowed) return

        Thread({
            try {
                val tunnel = when (route) {
                    Route.DIRECT -> directWs(dc, isMedia, quiet = true)
                    Route.CF -> cfWs(dc, isMedia, quiet = true)
                    Route.TCP -> null
                } ?: return@Thread
                offerPool(dc, isMedia, route, tunnel)
            } catch (_: Throwable) {
                // The next real connection will simply open its own tunnel.
            }
        }, "tgws-pool").apply {
            isDaemon = true
            start()
        }
    }

    /** Drops spare tunnels that expired or were closed by the server, even when idle. */
    private fun startPoolCleaner() {
        Thread({
            while (running) {
                try {
                    Thread.sleep(5_000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                val now = System.currentTimeMillis()
                val dead = synchronized(poolLock) {
                    val iterator = pool.iterator()
                    val expired = ArrayList<Pooled>()
                    while (iterator.hasNext()) {
                        val entry = iterator.next()
                        if (now - entry.at > POOL_TTL_MS || !entry.tunnel.isAlive) {
                            iterator.remove()
                            expired.add(entry)
                        }
                    }
                    expired
                }
                for (entry in dead) runCatching { entry.tunnel.close() }
            }
        }, "tgws-pool-gc").apply {
            isDaemon = true
            start()
        }
    }

    /** Spare tunnels turned out to be dead; stop using them for a minute. */
    private fun markPoolBad() {
        val now = System.currentTimeMillis()
        if (now < pooledDisabledUntil) return
        pooledDisabledUntil = now + 60_000
        val dead = synchronized(poolLock) {
            val copy = pool.toList()
            pool.clear()
            copy
        }
        for (entry in dead) runCatching { entry.tunnel.close() }
        log("Готовые соединения отклоняются — временно подключаюсь напрямую")
    }

    /**
     * Starts several route probes together and returns the first tunnel that opens.
     * Losing or late tunnels are closed, so nothing leaks when one path is much faster.
     */
    private fun raceRoutes(
        candidates: List<Pair<Route, () -> Tunnel?>>,
        windowMs: Long,
    ): Pair<Route, Tunnel>? {
        if (candidates.isEmpty()) return null
        val lock = Object()
        var finished = false
        var winner: Pair<Route, Tunnel>? = null
        val latch = CountDownLatch(1)

        for ((route, open) in candidates) {
            Thread({
                try {
                    val tunnel = open() ?: return@Thread
                    var adopted = false
                    synchronized(lock) {
                        if (!finished && winner == null) {
                            winner = route to tunnel
                            adopted = true
                            latch.countDown()
                        }
                    }
                    if (!adopted) runCatching { tunnel.close() }
                } catch (_: Throwable) {
                    // The other route may still work.
                }
            }, "tgws-route-race").apply {
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

    /**
     * Direct WebSocket to a Telegram DC. Candidates are raced in parallel so a blocked
     * IP or a missing certificate does not add a timeout per attempt:
     *  - the IP from the DC map with the kws SNI (the normal path),
     *  - the same IP with `sprinthost.ru` SNI and no hostname check ("fronting"),
     *  - the IP the kws domain itself resolves to, in case only the mapped IP is blocked.
     */
    private fun directWs(dc: Int, isMedia: Boolean, quiet: Boolean = false): Tunnel? {
        val mapDc = if (dc == 203) 2 else dc
        val mapped = config.dcMap[mapDc]
        val domains = DcInfo.wsDomains(dc, isMedia)

        val candidates = ArrayList<Pair<String, () -> RawWebSocket>>()
        if (mapped != null) {
            for (domain in domains) {
                candidates.add(
                    "$domain@$mapped" to {
                        RawWebSocket.connect(mapped, domain, DcInfo.WS_PATH, domain, true, 6000, 6000)
                    },
                )
                candidates.add(
                    "$domain@$mapped фронтинг" to {
                        RawWebSocket.connect(
                            mapped, domain, DcInfo.WS_PATH, "sprinthost.ru", false, 6000, 6000,
                        )
                    },
                )
            }
        }
        for (domain in domains) {
            for (address in Dns.resolve(domain)) {
                val ip = address.hostAddress ?: continue
                if (ip == mapped) continue
                candidates.add(
                    "$domain@$ip" to {
                        RawWebSocket.connect(ip, domain, DcInfo.WS_PATH, domain, true, 5000, 5000)
                    },
                )
            }
        }
        if (candidates.isEmpty()) return null

        val errors = Collections.synchronizedList(ArrayList<Pair<String, String>>())
        val started = System.currentTimeMillis()
        val winner = raceWs(candidates, 5000, errors) ?: run {
            if (!quiet) log("WS DC$dc: ${summarize(errors).ifEmpty { "нет кандидатов" }}")
            return null
        }
        if (!quiet) log("WS ${winner.first} (${System.currentTimeMillis() - started} мс)")
        return WsTunnel(winner.second)
    }

    /**
     * Cloudflare-proxied fallback: kws{dc}.<domain>, resolved through [Dns].
     * The domain that worked last time is tried on its own first; only if it fails are
     * the rest raced. Domains that failed stay on a five-minute cooldown, so a fresh
     * connection normally costs one round-trip instead of ten.
     */
    private fun cfWs(dc: Int, isMedia: Boolean, quiet: Boolean = false): Tunnel? {
        val id = if (dc == 203) 2 else dc
        val now = System.currentTimeMillis()

        val ordered = LinkedHashSet<String>()
        workingCfDomain?.let { ordered.add(it) }
        for (base in cfDomains) {
            if (ordered.contains(base)) continue
            if ((cfDeadUntil[base] ?: 0L) > now) continue
            ordered.add(base)
        }
        if (ordered.isEmpty()) {
            cfDeadUntil.clear()
            ordered.addAll(cfDomains)
        }
        if (ordered.isEmpty()) return null

        fun candidate(base: String): Pair<String, () -> RawWebSocket> {
            val domain = "kws$id.$base"
            return Pair(domain) {
                RawWebSocket.connect(
                    domain, domain, DcInfo.WS_PATH, domain, true, 6000, 6000,
                    Dns.resolveCf(domain),
                )
            }
        }

        // Fast path: the domain that worked last time, alone.
        val known = workingCfDomain
        if (known != null && (cfDeadUntil[known] ?: 0L) <= now) {
            val soloErrors = Collections.synchronizedList(ArrayList<Pair<String, String>>())
            val soloStarted = System.currentTimeMillis()
            val solo = raceWs(listOf(candidate(known)), 3500, soloErrors)
            if (solo != null) {
                val elapsed = System.currentTimeMillis() - soloStarted
                // Only a slow fast path is worth a line; the normal one is ~0.5 s and
                // would otherwise flood the log with one entry per connection.
                if (!quiet && elapsed > 1200) log("CF ${solo.first} ($elapsed мс)")
                return WsTunnel(solo.second)
            }
            cfDeadUntil[known] = now + 300_000
            ordered.remove(known)
        }
        if (ordered.isEmpty()) {
            cfDeadUntil.clear()
            ordered.addAll(cfDomains)
        }
        if (ordered.isEmpty()) return null

        val candidates = ordered.take(8).map { candidate(it) }
        val errors = Collections.synchronizedList(ArrayList<Pair<String, String>>())
        val started = System.currentTimeMillis()
        val winner = raceWs(candidates, 10_000, errors) ?: run {
            if (!quiet) log("CF: нет рабочих доменов (${summarize(errors)})")
            return null
        }

        val base = winner.first.substringAfter("kws$id.")
        val changed = workingCfDomain != base
        workingCfDomain = base
        cfDeadUntil.clear()
        val elapsed = System.currentTimeMillis() - started
        if (!quiet && (changed || elapsed > 1200)) log("CF ${winner.first} ($elapsed мс)")
        for ((label, _) in errors) {
            val failed = label.removePrefix("kws$id.")
            if (failed in cfDomains) cfDeadUntil[failed] = now + 300_000
        }
        return WsTunnel(winner.second)
    }

    /**
     * Starts every candidate concurrently and returns the first successful one.
     * Losers are closed as soon as the winner is known (or when they finish late).
     */
    private fun raceWs(
        candidates: List<Pair<String, () -> RawWebSocket>>,
        windowMs: Long,
        errors: MutableList<Pair<String, String>>,
    ): Pair<String, RawWebSocket>? = WsRace.run(candidates, windowMs, errors)

    private fun shortError(t: Throwable): String = WsRace.shortError(t)

    /** Turns many per-candidate failures into one readable line: `HTTP 503 ×4, timeout ×2`. */
    private fun summarize(errors: List<Pair<String, String>>): String = WsRace.summarize(errors)

    /** Downloads the current CF domain list; the embedded one goes stale over time. */
    private fun refreshCfDomains() {
        Thread({
            try {
                val connection = URL(CF_DOMAINS_URL).openConnection() as HttpsURLConnection
                connection.connectTimeout = 8000
                connection.readTimeout = 8000
                connection.setRequestProperty("user-agent", "Thymus")
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                connection.disconnect()

                val decoded = body.lineSequence()
                    .map { it.trim() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { DcInfo.decodeCfDomain(it) }
                    .filter { it.contains('.') }
                    .distinct()
                    .toList()
                if (decoded.size < 3) return@Thread
                if (decoded == cfDomains) return@Thread

                cfDomains = decoded
                cfDeadUntil.clear()
                workingCfDomain = null
                log("CF: список обновлён (${decoded.size} доменов)")
                onCfDomains?.invoke(decoded)
            } catch (_: Throwable) {
                // Offline or GitHub is blocked: the embedded list keeps working.
            }
        }, "tgws-cf-refresh").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Probes the routes once right after start, so the first connection from Telegram
     * does not have to discover that the direct path is blocked. Also finds a working
     * Cloudflare domain up front.
     *
     * Runs entirely on a worker thread: this used to wait for the probes on the caller,
     * which is the app's main thread — that is what made Android show "app isn't
     * responding" for up to 25 seconds after pressing Start.
     */
    private fun warmup() {
        Thread({ runWarmup() }, "tgws-warmup").apply {
            isDaemon = true
            start()
        }
    }

    private fun runWarmup() {
        val directDcs = listOf(2, 4).filter { config.dcMap.containsKey(it) }
        val directOk = ConcurrentHashMap<Int, Boolean>()
        val cfOk = AtomicBoolean(false)
        val latch = CountDownLatch(directDcs.size + 1)

        for (dc in directDcs) {
            Thread({
                try {
                    val direct = directWs(dc, false)
                    if (direct != null) {
                        directOk[dc] = true
                        // Keep it instead of closing: the first connection from Telegram
                        // can then skip the TLS/WS upgrade entirely.
                        offerPool(dc, false, Route.DIRECT, direct)
                    }
                } finally {
                    latch.countDown()
                }
            }, "tgws-warmup-direct").apply {
                isDaemon = true
                start()
            }
        }
        Thread({
            try {
                val cf = cfWs(2, false)
                if (cf != null) {
                    cfOk.set(true)
                    offerPool(2, false, Route.CF, cf)
                }
            } finally {
                latch.countDown()
            }
        }, "tgws-warmup-cf").apply {
            isDaemon = true
            start()
        }

        latch.await(25, TimeUnit.SECONDS)
        val parts = ArrayList<String>()
        for (dc in directDcs) {
            if (directOk[dc] == true) {
                preferredRoutes[dc] = Route.DIRECT
                parts.add("DC$dc напрямую ✓")
            } else {
                if (config.cfEnabled && cfOk.get()) preferredRoutes[dc] = Route.CF
                parts.add("DC$dc напрямую ✗")
            }
        }
        if (config.cfEnabled) parts.add(if (cfOk.get()) "CF ✓" else "CF ✗")
        log("Проверка: " + parts.joinToString(" · "))
    }

    private fun openTcp(dc: Int, isTest: Boolean): Tunnel? {
        val table = if (isTest) DcInfo.TEST_IPS else DcInfo.DEFAULT_IPS
        val ip = table[dc] ?: return null
        return try {
            val tunnel = TcpTunnel.connect(ip, 443)
            log("TCP $ip")
            tunnel
        } catch (t: Throwable) {
            log("TCP $ip: ${t.message}")
            null
        }
    }

    private fun bridge(
        client: Socket,
        cin: InputStream,
        cout: OutputStream,
        tunnel: Tunnel,
        ctx: CryptoContext,
        splitter: MsgSplitter,
    ) {
        val closed = AtomicBoolean(false)

        fun shutdown() {
            if (closed.compareAndSet(false, true)) {
                runCatching { tunnel.close() }
                runCatching { client.close() }
            }
        }

        val up = Thread({
            val buf = ByteArray(64 * 1024)
            try {
                while (true) {
                    val n = cin.read(buf)
                    if (n < 0) break
                    if (n == 0) continue
                    bytesUp.addAndGet(n.toLong())
                    val plain = ctx.clientDec.update(buf, 0, n)
                    val encrypted = ctx.tgEnc.update(plain)
                    val parts = splitter.split(encrypted, plain)
                    if (parts.size == 1) {
                        tunnel.send(parts[0])
                    } else if (parts.size > 1) {
                        for (part in parts) tunnel.send(part)
                    }
                }
                splitter.flush()?.let { tunnel.send(it) }
            } catch (_: Throwable) {
                // The other direction (or the client) closed the socket.
            } finally {
                shutdown()
            }
        }, "tgws-up")

        val down = Thread({
            try {
                while (true) {
                    val data = tunnel.recv() ?: break
                    if (data.isEmpty()) continue
                    bytesDown.addAndGet(data.size.toLong())
                    val plain = ctx.tgDec.update(data)
                    val encrypted = ctx.clientEnc.update(plain)
                    cout.write(encrypted)
                    cout.flush()
                }
            } catch (_: Throwable) {
                // Closed locally or by the peer.
            } finally {
                shutdown()
            }
        }, "tgws-down")

        up.isDaemon = true
        down.isDaemon = true
        up.start()
        down.start()
        up.join()
        down.join()
    }

    private fun readHandshake(input: InputStream): ByteArray? {
        val buf = ByteArray(MtProto.HANDSHAKE_LEN)
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) return null
            off += n
        }
        return buf
    }

    private companion object {
        const val CF_DOMAINS_URL =
            "https://raw.githubusercontent.com/QkartBismuth/Thymus/main/app/src/main/assets/cfproxy-domains.txt"

        /** How long an unused upgraded connection may sit before it is dropped. */
        const val POOL_TTL_MS = 20_000L

        /** Minimum gap between refill attempts for the same DC: media flag. */
        const val REFILL_INTERVAL_MS = 3_000L

        /** Hard cap so a weird client cannot make us hold dozens of idle sockets. */
        const val MAX_POOL = 6
    }
}
