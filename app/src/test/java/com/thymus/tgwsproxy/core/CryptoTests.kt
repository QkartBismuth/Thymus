package com.thymus.tgwsproxy.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Vectors were produced with the reference Python implementation
 * (pycryptodome-compatible AES-CTR from the `cryptography` package).
 */
class CryptoTests {

    private val secret = "000102030405060708090a0b0c0d0e0f".hexToBytes()
    private val packet = "030a11181f262d340102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30798edf555c9a7e5c".hexToBytes()
    private val relay = ("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" +
        "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f").hexToBytes()

    @Test
    fun parsesClientHandshake() {
        val hs = MtProto.parseHandshake(packet, secret)
        assertNotNull(hs)
        hs!!
        assertEquals(2, hs.dc)
        assertTrue(hs.isMedia)
        assertEquals(MtProto.PROTO_INTERMEDIATE_INT, hs.protoInt)
    }

    @Test
    fun rejectsWrongSecret() {
        val wrong = "ffffffffffffffffffffffffffffffff".hexToBytes()
        assertEquals(null, MtProto.parseHandshake(packet, wrong))
    }

    @Test
    fun keystreamsMatchReference() {
        val hs = MtProto.parseHandshake(packet, secret)!!
        val ctx = MtProto.buildCrypto(hs, secret, relay)
        val probe = ByteArray(16) { 0x11 }

        assertArrayEquals(
            "client decrypt stream",
            "6afe219c603cf32c3e950a8c153d459d".hexToBytes(),
            ctx.clientDec.update(probe),
        )
        assertArrayEquals(
            "client encrypt stream",
            "325ea54c1fd28b9f584f009b29bc2d97".hexToBytes(),
            ctx.clientEnc.update(probe),
        )
        assertArrayEquals(
            "relay encrypt stream",
            "04e240daab598cba6b84fe9952b3b445".hexToBytes(),
            ctx.tgEnc.update(probe),
        )
        assertArrayEquals(
            "relay decrypt stream",
            "5ec1ad5fe1b7d413095c609a4867b1f8".hexToBytes(),
            ctx.tgDec.update(probe),
        )
    }

    @Test
    fun relayInitDecryptsToTagAndDc() {
        val tag = byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
        val init = MtProto.buildRelayInit(tag, -4)

        // The relay init uses plain obfuscation: the key is used as-is, without the secret.
        val key = init.copyOfRange(8, 40)
        val iv = init.copyOfRange(40, 56)
        val plain = CtrStream(key, iv).update(init)

        assertArrayEquals(tag, plain.copyOfRange(56, 60))
        val dcIdx = ((plain[60].toInt() and 0xFF) or ((plain[61].toInt() and 0xFF) shl 8)).toShort().toInt()
        assertEquals(-4, dcIdx)
    }

    @Test
    fun splitsIntermediatePackets() {
        val pkt1 = "0500000068656c6c6f".hexToBytes()
        val pkt2 = "03000000616263".hexToBytes()
        val splitter = MsgSplitter(MtProto.PROTO_INTERMEDIATE_INT)

        val stream = pkt1 + pkt2
        val parts = splitter.split(stream, stream)
        assertEquals(2, parts.size)
        assertArrayEquals(pkt1, parts[0])
        assertArrayEquals(pkt2, parts[1])

        val splitter2 = MsgSplitter(MtProto.PROTO_INTERMEDIATE_INT)
        val firstHalf = pkt1 + pkt2.copyOfRange(0, 2)
        val first = splitter2.split(firstHalf, firstHalf)
        assertEquals(1, first.size)
        assertArrayEquals(pkt1, first[0])

        val secondHalf = pkt2.copyOfRange(2, pkt2.size)
        val second = splitter2.split(secondHalf, secondHalf)
        assertEquals(1, second.size)
        assertArrayEquals(pkt2, second[0])
    }

    @Test
    fun cfDomainsAreDecoded() {
        val domains = DcInfo.DEFAULT_CF_DOMAINS
        assertTrue(domains.isNotEmpty())
        assertTrue(domains.all { it.endsWith(".co.uk") && !it.contains(".com") })
    }
}
