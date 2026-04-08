import unittest
from io import BytesIO
from pyrdp.parser.rdp.ntlmssp import NTLMSSPParser


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
