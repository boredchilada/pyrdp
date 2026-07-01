import unittest
from io import BytesIO
from pyrdp.parser.rdp.ntlmssp import NTLMSSPParser


class TestRichNTLMChallenge(unittest.TestCase):
    def test_challenge_contains_avpairs(self):
        parser = NTLMSSPParser()
        challenge = b'\x00' * 8
        data = parser.writeNTLMSSPChallenge(
            "CONTOSO", challenge,
            nbDomain="CONTOSO", nbComputer="DC01",
            dnsDomain="contoso.local", dnsComputer="dc01.contoso.local",
        )
        self.assertGreater(len(data), 0)
        # Should contain NTLMSSP signature somewhere
        self.assertIn(b'NTLMSSP\x00', data)
        # Should contain UTF-16LE encoded domain/computer names
        self.assertIn("CONTOSO".encode('utf-16le'), data)
        self.assertIn("DC01".encode('utf-16le'), data)
        self.assertIn("contoso.local".encode('utf-16le'), data)
        self.assertIn("dc01.contoso.local".encode('utf-16le'), data)

    def test_challenge_contains_timestamp(self):
        import struct
        parser = NTLMSSPParser()
        data = parser.writeNTLMSSPChallenge("TEST", b'\x00' * 8)
        # MsvAvTimestamp AV_PAIR ID is 0x0007
        # Search for the 2-byte LE encoding of 0x0007 followed by 2-byte LE 0x0008 (length=8)
        marker = struct.pack('<HH', 0x0007, 8)
        self.assertIn(marker, data)

    def test_challenge_contains_eol(self):
        import struct
        parser = NTLMSSPParser()
        data = parser.writeNTLMSSPChallenge("TEST", b'\x00' * 8)
        marker = struct.pack('<HH', 0x0000, 0)
        self.assertIn(marker, data)

    def test_challenge_default_identity(self):
        parser = NTLMSSPParser()
        data = parser.writeNTLMSSPChallenge("MYHOST", b'\x00' * 8)
        self.assertIn("MYHOST".encode('utf-16le'), data)
        self.assertIn("myhost".encode('utf-16le'), data)  # dns defaults to lowercase


class TestNegotiatePDUParsing(unittest.TestCase):
    def test_parse_negotiate_with_flags(self):
        import struct
        # Build a minimal NTLM NEGOTIATE (Type 1)
        msg = bytearray()
        msg.extend(b'NTLMSSP\x00')
        msg.extend(struct.pack('<I', 1))  # messageType = NEGOTIATE
        flags = 0xE2088297  # common flags
        msg.extend(struct.pack('<I', flags))
        # Domain fields (empty)
        msg.extend(struct.pack('<HHI', 0, 0, 0))
        # Workstation fields (empty)
        msg.extend(struct.pack('<HHI', 0, 0, 0))
        parser = NTLMSSPParser()
        # Wrap in enough context for findMessage
        pdu = parser.doParse(bytes(msg))
        self.assertEqual(pdu.messageType, 1)
        self.assertEqual(pdu.negotiateFlags, flags)


class TestNTLMFlagDecode(unittest.TestCase):
    def test_decode_common_flags(self):
        from pyrdp.enum.ntlmssp import decodeNTLMFlags
        flags = 0xE28A8215
        decoded = decodeNTLMFlags(flags)
        self.assertTrue(decoded["unicode"])
        self.assertTrue(decoded["ntlm"])
        self.assertTrue(decoded["128bit"])
        self.assertTrue(decoded["56bit"])
        self.assertTrue(decoded["target_info"])
        self.assertFalse(decoded["datagram"])


class TestTSRequestError(unittest.TestCase):
    def test_writeTSRequestError_is_valid_ber(self):
        parser = NTLMSSPParser()
        data = parser.writeTSRequestError(version=6, errorCode=0xC000006D)
        self.assertGreater(len(data), 0)
        self.assertEqual(data[0], 0x30)  # BER SEQUENCE tag

    def test_writeTSRequestError_version_present(self):
        parser = NTLMSSPParser()
        data = parser.writeTSRequestError(version=6, errorCode=0xC000006D)
        stream = BytesIO(data)
        from pyrdp.core import ber
        self.assertTrue(ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True))
        ber.readLength(stream)
        self.assertTrue(ber.readContextualTag(stream, 0, True))
        version = ber.readInteger(stream)
        self.assertEqual(version, 6)


if __name__ == "__main__":
    unittest.main()
