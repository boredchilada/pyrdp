import unittest
from pyrdp.core.proxy_protocol import ProxyProtocolHeader, parseProxyProtocol


class TestProxyProtocolV1(unittest.TestCase):
    def test_parse_tcp4(self):
        data = b"PROXY TCP4 192.168.1.100 10.0.0.1 56324 3389\r\n"
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "192.168.1.100")
        self.assertEqual(header.dstAddr, "10.0.0.1")
        self.assertEqual(header.srcPort, 56324)
        self.assertEqual(header.dstPort, 3389)
        self.assertEqual(header.family, "TCP4")
        self.assertEqual(header.command, "PROXY")
        self.assertEqual(header.rawLength, len(data))

    def test_parse_tcp6(self):
        data = b"PROXY TCP6 2001:db8::1 2001:db8::2 56324 3389\r\n"
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "2001:db8::1")
        self.assertEqual(header.dstAddr, "2001:db8::2")
        self.assertEqual(header.srcPort, 56324)
        self.assertEqual(header.dstPort, 3389)
        self.assertEqual(header.family, "TCP6")

    def test_parse_unknown(self):
        data = b"PROXY UNKNOWN\r\n"
        header = parseProxyProtocol(data)
        self.assertIsNone(header.srcAddr)
        self.assertIsNone(header.dstAddr)
        self.assertIsNone(header.srcPort)
        self.assertIsNone(header.dstPort)
        self.assertEqual(header.family, "UNKNOWN")
        self.assertEqual(header.rawLength, len(data))

    def test_v1_remainder_returned(self):
        rdp_data = b"\x03\x00\x00\x13"
        data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 3389\r\n" + rdp_data
        header = parseProxyProtocol(data)
        self.assertEqual(header.rawLength, len(data) - len(rdp_data))

    def test_v1_reject_no_crlf(self):
        data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 3389"
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)

    def test_v1_reject_bad_port(self):
        data = b"PROXY TCP4 1.2.3.4 5.6.7.8 99999 3389\r\n"
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)


if __name__ == "__main__":
    unittest.main()
