package com.thymus.tgwsproxy.core

import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Manual check against a proxy running on a real phone, reached through
 * `adb forward tcp:14430 tcp:1443`. Measures a cold connection and the next one,
 * which should come out of the engine's spare pool:
 *
 *     adb forward tcp:14430 tcp:1443
 *     ./gradlew test --tests "*ForwardedProxyTest*" \
 *         -Dtgws.remotePort=14430 -Dtgws.remoteSecret=<secret without dd>
 *
 * Skipped unless both properties are set.
 */
class ForwardedProxyTest {

    @Test
    fun measuresColdAndPooledSetup() {
        val port = System.getProperty("tgws.remotePort")?.toIntOrNull()
        val secret = System.getProperty("tgws.remoteSecret")
        assumeTrue(port != null && secret != null && secret.length == 32)

        val coldStarted = System.currentTimeMillis()
        LocalProbe(port!!, secret!!, 2).use { it.ping() }
        println("cold setup: ${System.currentTimeMillis() - coldStarted} ms")

        // The engine prepares the next tunnel in the background right after a connection.
        Thread.sleep(4_000)

        val pooledStarted = System.currentTimeMillis()
        LocalProbe(port, secret, 2).use {
            val rtt = it.ping()
            println("pooled setup: ${System.currentTimeMillis() - pooledStarted} ms, rtt=$rtt ms")
        }
    }
}
