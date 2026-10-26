package com.thymus.tgwsproxy.bypass

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BypassConfigParserTest {

    @Test
    fun readsAZapretGeneralConfig() {
        val text = """
            @echo off
            start "" winws.exe --wf-tcp=80,443 --filter-tcp=443 --hostlist="%LISTS%list-google.txt" --dpi-desync=multisplit --dpi-desync-split-pos=1 --dpi-desync-repeats=6 --new ^
            --filter-tcp=80,443 --hostlist-domains=youtube.com,discord.media --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-repeats=6 --new ^
            --filter-udp=443 --dpi-desync=fake --dpi-desync-fake-quic="%BIN%quic.bin"
        """.trimIndent()

        val result = BypassConfigParser.parse(text, "general")
        assertTrue(result is BypassConfigParser.Result.Success)
        val profile = (result as BypassConfigParser.Result.Success).profile
        assertTrue(profile.ports.containsAll(listOf(80, 443)))
        assertTrue(profile.splitPositions.containsAll(listOf("1", "midsld")))
        assertEquals(BypassProfile.MAX_OOB_REPEATS, profile.oobRepeats)
        assertTrue(profile.oob)
        assertTrue(
            "a global section makes the whole config apply to every host",
            profile.hosts.isEmpty(),
        )
        assertTrue("fake QUIC packets must be reported", profile.warnings.contains("quic fake"))
        assertTrue("unreadable hostlists must be reported", profile.warnings.contains("hostlist"))
        assertTrue(profile.toStrategy().active)
    }

    @Test
    fun acceptsFakeOnlyConfigsAndApproximatesThem() {
        // general (ALT) and general (SIMPLE FAKE) contain no split mode at all: zapret
        // only sends a fake packet. Thymus must still import them as a split + OOB.
        val text = """
            winws.exe --filter-tcp=443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake,fakedsplit --dpi-desync-repeats=6 --dpi-desync-fooling=ts
        """.trimIndent()

        val result = BypassConfigParser.parse(text, "general (ALT)")
        assertTrue(result is BypassConfigParser.Result.Success)
        val profile = (result as BypassConfigParser.Result.Success).profile
        assertTrue(profile.oob)
        assertEquals(listOf("midsld"), profile.splitPositions)
        assertTrue(profile.warnings.contains("fake"))
        assertTrue(profile.warnings.contains("fakedsplit"))
    }

    @Test
    fun readsTheNativeFormat() {
        val text = """
            # my config
            name=My bypass
            desync=multisplit,oob
            split-pos=1,midsld
            oob=1
            repeats=3
            ports=443
            hosts=youtube.com, discord.com
            quic=drop
        """.trimIndent()

        val result = BypassConfigParser.parse(text, "fallback")
        assertTrue(result is BypassConfigParser.Result.Success)
        val profile = (result as BypassConfigParser.Result.Success).profile
        assertEquals("My bypass", profile.name)
        assertEquals(listOf("1", "midsld"), profile.splitPositions)
        assertTrue(profile.oob)
        assertEquals(3, profile.oobRepeats)
        assertEquals(setOf(443), profile.ports)
        assertEquals(listOf("youtube.com", "discord.com"), profile.hosts)
        assertFalse(profile.quicRelay)
        val strategy = profile.toStrategy()
        assertTrue(strategy.appliesToHost("www.youtube.com"))
        assertFalse(strategy.appliesToHost("example.org"))
        assertTrue(strategy.appliesToPort(443))
        assertFalse(strategy.appliesToPort(80))
    }

    @Test
    fun nativePassthroughIsAcceptedButInactive() {
        val result = BypassConfigParser.parse("desync=none\noob=0", "off")
        assertTrue(result is BypassConfigParser.Result.Success)
        val profile = (result as BypassConfigParser.Result.Success).profile
        assertFalse(profile.toStrategy().active)
    }

    @Test
    fun oobFlagWorksWithoutTheOobMode() {
        val result = BypassConfigParser.parse("desync=split\nsplit-pos=1\noob=1", "oob")
        assertTrue(result is BypassConfigParser.Result.Success)
        val profile = (result as BypassConfigParser.Result.Success).profile
        assertTrue(profile.oob)
        assertTrue(profile.toStrategy().active)
    }

    @Test
    fun rejectsTextWithoutAnyDesync() {
        val result = BypassConfigParser.parse("just some notes\nnothing to do", "broken")
        assertTrue(result is BypassConfigParser.Result.Error)
    }

    @Test
    fun serializedNativeConfigCanBeReadBack() {
        val original = BypassProfile(
            id = "custom-1",
            name = "Round trip",
            description = "OOB + 1 + midsld",
            splitPositions = listOf("1", "midsld"),
            oob = true,
            oobRepeats = 2,
            ports = setOf(443),
            hosts = listOf("youtube.com"),
            quicRelay = false,
            warnings = listOf("fake"),
        )
        val text = BypassConfigs.serialize(original)
        val result = BypassConfigParser.parse(text, "Round trip")
        assertTrue(result is BypassConfigParser.Result.Success)
        val profile = (result as BypassConfigParser.Result.Success).profile
        assertEquals(original.name, profile.name)
        assertEquals(original.splitPositions, profile.splitPositions)
        assertTrue(profile.oob)
        assertEquals(original.oobRepeats, profile.oobRepeats)
        assertEquals(original.ports, profile.ports)
        assertEquals(original.hosts, profile.hosts)
        assertFalse(profile.quicRelay)
        assertTrue(profile.warnings.contains("fake"))
    }
}
