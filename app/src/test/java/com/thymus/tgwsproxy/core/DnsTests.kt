package com.thymus.tgwsproxy.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress

class DnsTests {

    @Test
    fun recognisesCloudflareRanges() {
        assertTrue(Dns.isCloudflare(InetAddress.getByName("104.21.43.90")))
        assertTrue(Dns.isCloudflare(InetAddress.getByName("172.67.177.105")))
        assertTrue(Dns.isCloudflare(InetAddress.getByName("162.159.1.1")))
        assertFalse(Dns.isCloudflare(InetAddress.getByName("149.154.167.220")))
        assertFalse(Dns.isCloudflare(InetAddress.getByName("8.8.8.8")))
        assertFalse(Dns.isCloudflare(InetAddress.getByName("10.0.0.1")))
    }

    @Test
    fun literalAddressesAreNotResolvedThroughDns() {
        val addresses = Dns.resolve("149.154.167.220")
        assertEquals(1, addresses.size)
        assertEquals("149.154.167.220", addresses[0].hostAddress)
    }

    @Test
    fun resolvesCloudflareFrontDomain() {
        assumeTrue(System.getProperty("tgws.netTest") == "1")
        val addresses = Dns.resolveCf("kws2.offshor.co.uk")
        assertTrue("no addresses", addresses.isNotEmpty())
        assertTrue(
            "not a Cloudflare IP: ${addresses.map { it.hostAddress }}",
            addresses.any { Dns.isCloudflare(it) },
        )
    }
}
