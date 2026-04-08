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


import struct


class TestProxyProtocolV2(unittest.TestCase):
    def _buildV2Header(self, command, family, addrData, tlvData=b''):
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        ver_cmd = 0x20 | (command & 0x0F)
        length = len(addrData) + len(tlvData)
        header = sig + struct.pack('!BBH', ver_cmd, family, length)
        return header + addrData + tlvData

    def test_parse_ipv4_tcp(self):
        import socket
        srcAddr = socket.inet_aton("192.168.1.100")
        dstAddr = socket.inet_aton("10.0.0.1")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 56324, 3389)
        data = self._buildV2Header(0x01, 0x11, addrData)
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "192.168.1.100")
        self.assertEqual(header.dstAddr, "10.0.0.1")
        self.assertEqual(header.srcPort, 56324)
        self.assertEqual(header.dstPort, 3389)
        self.assertEqual(header.command, "PROXY")

    def test_parse_ipv6_tcp(self):
        import socket
        srcAddr = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        dstAddr = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 56324, 3389)
        data = self._buildV2Header(0x01, 0x21, addrData)
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "2001:db8::1")
        self.assertEqual(header.dstAddr, "2001:db8::2")
        self.assertEqual(header.srcPort, 56324)
        self.assertEqual(header.dstPort, 3389)

    def test_parse_local_command(self):
        data = self._buildV2Header(0x00, 0x00, b'')
        header = parseProxyProtocol(data)
        self.assertEqual(header.command, "LOCAL")
        self.assertIsNone(header.srcAddr)

    def test_v2_with_tlv_extensions(self):
        import socket
        srcAddr = socket.inet_aton("1.2.3.4")
        dstAddr = socket.inet_aton("5.6.7.8")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 1234, 3389)
        tlv = struct.pack('!BH', 0x01, 3) + b'rdp'
        data = self._buildV2Header(0x01, 0x11, addrData, tlv)
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "1.2.3.4")
        self.assertEqual(header.rawLength, len(data))

    def test_v2_remainder_not_consumed(self):
        import socket
        srcAddr = socket.inet_aton("1.2.3.4")
        dstAddr = socket.inet_aton("5.6.7.8")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 1234, 3389)
        data = self._buildV2Header(0x01, 0x11, addrData) + b"\x03\x00\x00\x13"
        header = parseProxyProtocol(data)
        self.assertEqual(header.rawLength, len(data) - 4)

    def test_v2_reject_wrong_version(self):
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        data = sig + b'\x31\x11\x00\x0C' + b'\x00' * 12
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)

    def test_v2_reject_truncated(self):
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        data = sig + b'\x21\x11\x00\x0C' + b'\x00' * 8
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)


class TestAutoDetect(unittest.TestCase):
    def test_detect_v1(self):
        data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 3389\r\n"
        header = parseProxyProtocol(data)
        self.assertEqual(header.family, "TCP4")

    def test_detect_v2(self):
        import socket
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        srcAddr = socket.inet_aton("1.2.3.4")
        dstAddr = socket.inet_aton("5.6.7.8")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 1234, 3389)
        data = sig + struct.pack('!BBH', 0x21, 0x11, len(addrData)) + addrData
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "1.2.3.4")

    def test_detect_invalid(self):
        data = b"\x03\x00\x00\x13"
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)


if __name__ == "__main__":
    unittest.main()
