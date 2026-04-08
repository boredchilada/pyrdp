# PROXY Protocol v1/v2 Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow PyRDP to sit behind nginx/HAProxy/AWS NLB and see the real client IP via PROXY protocol.

**Architecture:** New `proxy_protocol.py` parser module, TCP layer state machine for buffering the header before passing data to RDP layers, config/CLI wiring. Pure additive — no changes to existing behavior when the flag is off.

**Tech Stack:** Python 3.7+, Twisted, struct (stdlib), unittest

**Spec:** `docs/superpowers/specs/2026-04-08-proxy-protocol-nla-improvements-design.md` — Feature 1

---

## File Map

| File | Responsibility |
|------|---------------|
| `pyrdp/core/proxy_protocol.py` | **NEW** — `ProxyProtocolHeader` dataclass, `parseV1()`, `parseV2()`, `parse()` auto-detect |
| `test/test_proxy_protocol.py` | **NEW** — Unit tests for parser |
| `pyrdp/layer/tcp.py` | **MODIFY** — Add buffering state machine to `TwistedTCPLayer.dataReceived()` |
| `pyrdp/mitm/TCPMITM.py` | **MODIFY** — Use `proxyInfo` for client IP in `onClientConnection()` |
| `pyrdp/mitm/config.py` | **MODIFY** — Add `proxyProtocol` field to `MITMConfig` |
| `pyrdp/mitm/cli.py` | **MODIFY** — Add `--proxy-protocol` argument, wire to config |
| `pyrdp/core/mitm.py` | **MODIFY** — Pass config to TCP layer so it knows to expect PROXY headers |

---

### Task 1: PROXY Protocol Parser — v1

**Files:**
- Create: `pyrdp/core/proxy_protocol.py`
- Create: `test/test_proxy_protocol.py`

- [ ] **Step 1: Write failing tests for v1 parsing**

```python
# test/test_proxy_protocol.py
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
        """Data after the header should not be consumed."""
        rdp_data = b"\x03\x00\x00\x13"  # TPKT header
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_proxy_protocol.py -v`
Expected: `ModuleNotFoundError: No module named 'pyrdp.core.proxy_protocol'`

- [ ] **Step 3: Implement v1 parser**

```python
# pyrdp/core/proxy_protocol.py
#
# This file is part of the PyRDP project.
# Copyright (C) 2026 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
PROXY protocol v1/v2 parser.
Spec: https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt
"""

import struct
from dataclasses import dataclass
from typing import Optional


V2_SIGNATURE = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
V1_PREFIX = b'PROXY'
V1_MAX_LENGTH = 107


@dataclass
class ProxyProtocolHeader:
    """Parsed PROXY protocol header."""
    srcAddr: Optional[str]
    srcPort: Optional[int]
    dstAddr: Optional[str]
    dstPort: Optional[int]
    family: str          # "TCP4", "TCP6", "UNKNOWN", "AF_INET", "AF_INET6", "AF_UNSPEC"
    command: str         # "PROXY" or "LOCAL"
    rawLength: int       # Total bytes consumed by the header (so caller can slice remainder)


def parseV1(data: bytes) -> ProxyProtocolHeader:
    """Parse a PROXY protocol v1 (text) header."""
    crlf = data.find(b'\r\n')
    if crlf == -1:
        if len(data) >= V1_MAX_LENGTH:
            raise ValueError("PROXY v1 header exceeds 107 bytes without CRLF")
        raise ValueError("Incomplete PROXY v1 header: no CRLF found")

    line = data[:crlf].decode('ascii')
    rawLength = crlf + 2  # include \r\n

    parts = line.split(' ')
    if parts[0] != 'PROXY':
        raise ValueError(f"Invalid PROXY v1 header: expected 'PROXY', got '{parts[0]}'")

    proto = parts[1]

    if proto == 'UNKNOWN':
        return ProxyProtocolHeader(
            srcAddr=None, srcPort=None, dstAddr=None, dstPort=None,
            family="UNKNOWN", command="PROXY", rawLength=rawLength
        )

    if proto not in ('TCP4', 'TCP6'):
        raise ValueError(f"Invalid PROXY v1 protocol: '{proto}'")

    if len(parts) != 6:
        raise ValueError(f"Invalid PROXY v1 header: expected 6 fields, got {len(parts)}")

    srcAddr = parts[2]
    dstAddr = parts[3]
    srcPort = int(parts[4])
    dstPort = int(parts[5])

    if not (0 <= srcPort <= 65535) or not (0 <= dstPort <= 65535):
        raise ValueError(f"Invalid port number: src={srcPort} dst={dstPort}")

    return ProxyProtocolHeader(
        srcAddr=srcAddr, srcPort=srcPort, dstAddr=dstAddr, dstPort=dstPort,
        family=proto, command="PROXY", rawLength=rawLength
    )


def parseProxyProtocol(data: bytes) -> ProxyProtocolHeader:
    """Auto-detect and parse PROXY protocol v1 or v2 header."""
    if len(data) >= 12 and data[:12] == V2_SIGNATURE:
        return parseV2(data)
    elif len(data) >= 5 and data[:5] == V1_PREFIX:
        return parseV1(data)
    else:
        raise ValueError(f"Not a valid PROXY protocol header (first bytes: {data[:16].hex()})")


def parseV2(data: bytes) -> ProxyProtocolHeader:
    """Parse a PROXY protocol v2 (binary) header. Placeholder — implemented in Task 2."""
    raise NotImplementedError("v2 parsing not yet implemented")
```

- [ ] **Step 4: Run tests to verify v1 tests pass**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_proxy_protocol.py::TestProxyProtocolV1 -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/core/proxy_protocol.py test/test_proxy_protocol.py
git commit -m "feat: add PROXY protocol v1 parser with tests"
```

---

### Task 2: PROXY Protocol Parser — v2

**Files:**
- Modify: `pyrdp/core/proxy_protocol.py`
- Modify: `test/test_proxy_protocol.py`

- [ ] **Step 1: Write failing tests for v2 parsing**

Add to `test/test_proxy_protocol.py`:

```python
class TestProxyProtocolV2(unittest.TestCase):
    def _buildV2Header(self, command, family, addrData, tlvData=b''):
        """Helper to build a v2 binary header."""
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        ver_cmd = 0x20 | (command & 0x0F)
        length = len(addrData) + len(tlvData)
        header = sig + struct.pack('!BBH', ver_cmd, family, length)
        return header + addrData + tlvData

    def test_parse_ipv4_tcp(self):
        import socket, struct
        srcAddr = socket.inet_aton("192.168.1.100")
        dstAddr = socket.inet_aton("10.0.0.1")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 56324, 3389)
        data = self._buildV2Header(0x01, 0x11, addrData)  # PROXY, IPv4+TCP

        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "192.168.1.100")
        self.assertEqual(header.dstAddr, "10.0.0.1")
        self.assertEqual(header.srcPort, 56324)
        self.assertEqual(header.dstPort, 3389)
        self.assertEqual(header.command, "PROXY")

    def test_parse_ipv6_tcp(self):
        import socket, struct
        srcAddr = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        dstAddr = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 56324, 3389)
        data = self._buildV2Header(0x01, 0x21, addrData)  # PROXY, IPv6+TCP

        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "2001:db8::1")
        self.assertEqual(header.dstAddr, "2001:db8::2")
        self.assertEqual(header.srcPort, 56324)
        self.assertEqual(header.dstPort, 3389)

    def test_parse_local_command(self):
        data = self._buildV2Header(0x00, 0x00, b'')  # LOCAL, AF_UNSPEC
        header = parseProxyProtocol(data)
        self.assertEqual(header.command, "LOCAL")
        self.assertIsNone(header.srcAddr)

    def test_v2_with_tlv_extensions(self):
        import socket, struct
        srcAddr = socket.inet_aton("1.2.3.4")
        dstAddr = socket.inet_aton("5.6.7.8")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 1234, 3389)
        # PP2_TYPE_ALPN (0x01) with value "rdp"
        tlv = struct.pack('!BH', 0x01, 3) + b'rdp'
        data = self._buildV2Header(0x01, 0x11, addrData, tlv)

        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "1.2.3.4")
        self.assertEqual(header.rawLength, len(data))

    def test_v2_remainder_not_consumed(self):
        import socket, struct
        srcAddr = socket.inet_aton("1.2.3.4")
        dstAddr = socket.inet_aton("5.6.7.8")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 1234, 3389)
        data = self._buildV2Header(0x01, 0x11, addrData) + b"\x03\x00\x00\x13"

        header = parseProxyProtocol(data)
        self.assertEqual(header.rawLength, len(data) - 4)

    def test_v2_reject_bad_signature(self):
        data = b'\x00' * 16
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)

    def test_v2_reject_wrong_version(self):
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        data = sig + b'\x31\x11\x00\x0C' + b'\x00' * 12  # version 3, not 2
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)

    def test_v2_reject_truncated(self):
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        data = sig + b'\x21\x11\x00\x0C' + b'\x00' * 8  # says 12 bytes but only 8
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)


class TestAutoDetect(unittest.TestCase):
    def test_detect_v1(self):
        data = b"PROXY TCP4 1.2.3.4 5.6.7.8 1234 3389\r\n"
        header = parseProxyProtocol(data)
        self.assertEqual(header.family, "TCP4")

    def test_detect_v2(self):
        import socket, struct
        sig = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
        srcAddr = socket.inet_aton("1.2.3.4")
        dstAddr = socket.inet_aton("5.6.7.8")
        addrData = srcAddr + dstAddr + struct.pack('!HH', 1234, 3389)
        data = sig + struct.pack('!BBH', 0x21, 0x11, len(addrData)) + addrData
        header = parseProxyProtocol(data)
        self.assertEqual(header.srcAddr, "1.2.3.4")

    def test_detect_invalid(self):
        data = b"\x03\x00\x00\x13"  # TPKT header, not PROXY
        with self.assertRaises(ValueError):
            parseProxyProtocol(data)
```

- [ ] **Step 2: Run tests to verify v2 tests fail**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_proxy_protocol.py::TestProxyProtocolV2 -v`
Expected: FAIL with `NotImplementedError`

- [ ] **Step 3: Implement v2 parser**

Replace the `parseV2` stub in `pyrdp/core/proxy_protocol.py`:

```python
def parseV2(data: bytes) -> ProxyProtocolHeader:
    """Parse a PROXY protocol v2 (binary) header."""
    if len(data) < 16:
        raise ValueError(f"PROXY v2 header too short: {len(data)} bytes (need at least 16)")

    verCmd = data[12]
    version = (verCmd >> 4) & 0x0F
    command = verCmd & 0x0F

    if version != 0x02:
        raise ValueError(f"Unsupported PROXY v2 version: {version}")

    famProto = data[13]
    addrFamily = (famProto >> 4) & 0x0F
    transport = famProto & 0x0F

    addrLen = struct.unpack('!H', data[14:16])[0]

    if len(data) < 16 + addrLen:
        raise ValueError(f"PROXY v2 header truncated: need {16 + addrLen} bytes, got {len(data)}")

    rawLength = 16 + addrLen
    addrData = data[16:rawLength]

    commandStr = "PROXY" if command == 0x01 else "LOCAL"

    if command == 0x00 or addrFamily == 0x00:
        # LOCAL command or AF_UNSPEC — no address info
        return ProxyProtocolHeader(
            srcAddr=None, srcPort=None, dstAddr=None, dstPort=None,
            family="AF_UNSPEC", command=commandStr, rawLength=rawLength
        )

    if addrFamily == 0x01 and transport == 0x01:
        # AF_INET + STREAM (TCP4)
        if len(addrData) < 12:
            raise ValueError(f"PROXY v2 IPv4 address data too short: {len(addrData)}")
        import socket
        srcAddr = socket.inet_ntoa(addrData[0:4])
        dstAddr = socket.inet_ntoa(addrData[4:8])
        srcPort, dstPort = struct.unpack('!HH', addrData[8:12])
        family = "AF_INET"
    elif addrFamily == 0x02 and transport == 0x01:
        # AF_INET6 + STREAM (TCP6)
        if len(addrData) < 36:
            raise ValueError(f"PROXY v2 IPv6 address data too short: {len(addrData)}")
        import socket
        srcAddr = socket.inet_ntop(socket.AF_INET6, addrData[0:16])
        dstAddr = socket.inet_ntop(socket.AF_INET6, addrData[16:32])
        srcPort, dstPort = struct.unpack('!HH', addrData[32:36])
        family = "AF_INET6"
    else:
        raise ValueError(f"Unsupported PROXY v2 family/transport: 0x{famProto:02X}")

    return ProxyProtocolHeader(
        srcAddr=srcAddr, srcPort=srcPort, dstAddr=dstAddr, dstPort=dstPort,
        family=family, command=commandStr, rawLength=rawLength
    )
```

- [ ] **Step 4: Run all parser tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_proxy_protocol.py -v`
Expected: All tests PASS (v1, v2, auto-detect)

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/core/proxy_protocol.py test/test_proxy_protocol.py
git commit -m "feat: add PROXY protocol v2 parser with tests"
```

---

### Task 3: Config and CLI Wiring

**Files:**
- Modify: `pyrdp/mitm/config.py:18` (add field to `MITMConfig.__init__`)
- Modify: `pyrdp/mitm/cli.py:76-135` (add argument to `buildArgParser`, wire in `configure`)

- [ ] **Step 1: Add config field**

In `pyrdp/mitm/config.py`, add after line 91 (after `self.redirectionPort = None`):

```python
        self.proxyProtocol: bool = False
        """Whether to expect PROXY protocol headers on incoming connections."""
```

- [ ] **Step 2: Add CLI argument**

In `pyrdp/mitm/cli.py`, add to `buildArgParser()` after the `--nla-redirection-port` argument (line 132):

```python
    parser.add_argument("--proxy-protocol",
        help="Enable PROXY protocol v1/v2 support. Use when PyRDP is behind "
             "nginx, HAProxy, or AWS NLB. The proxy must send a PROXY protocol "
             "header so PyRDP can see the real client IP.",
        action="store_true")
```

- [ ] **Step 3: Wire CLI to config**

In `pyrdp/mitm/cli.py`, in the `configure()` function, after line 209 (after `config.sspChallenge = args.ssp_challenge`), add:

```python
    config.proxyProtocol = args.proxy_protocol
```

- [ ] **Step 4: Run existing tests to verify no regression**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All existing tests PASS

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/mitm/config.py pyrdp/mitm/cli.py
git commit -m "feat: add --proxy-protocol CLI flag and config field"
```

---

### Task 4: TCP Layer — PROXY Protocol Buffering

**Files:**
- Modify: `pyrdp/layer/tcp.py:37-109` (`TwistedTCPLayer`)
- Modify: `pyrdp/core/mitm.py:27-40` (`MITMServerFactory.buildProtocol`)

- [ ] **Step 1: Add state machine to TwistedTCPLayer**

In `pyrdp/layer/tcp.py`, add import at top:

```python
from pyrdp.core.proxy_protocol import ProxyProtocolHeader, parseProxyProtocol
```

Modify `TwistedTCPLayer.__init__` (line 45-49) to add proxy fields:

```python
    def __init__(self):
        self.log = logging.getLogger(LOGGER_NAMES.PYRDP)
        super().__init__(TCPParser())
        self.connectedEvent = asyncio.Event()
        self.logSSLRequired = False
        self.proxyProtocolEnabled = False
        self.proxyInfo: ProxyProtocolHeader = None
        self._proxyBuffer = b''
        self._proxyHeaderParsed = False
```

Replace `dataReceived` method (line 82-109) with:

```python
    def dataReceived(self, data: bytes):
        """
        Called whenever data is received.
        :param data: bytes received.
        """
        try:
            if self.proxyProtocolEnabled and not self._proxyHeaderParsed:
                self._proxyBuffer += data
                try:
                    self.proxyInfo = parseProxyProtocol(self._proxyBuffer)
                    self._proxyHeaderParsed = True
                    remainder = self._proxyBuffer[self.proxyInfo.rawLength:]
                    self._proxyBuffer = b''
                    self.log.debug("PROXY protocol: %(src)s:%(srcPort)s -> %(dst)s:%(dstPort)s (%(cmd)s)", {
                        "src": self.proxyInfo.srcAddr,
                        "srcPort": self.proxyInfo.srcPort,
                        "dst": self.proxyInfo.dstAddr,
                        "dstPort": self.proxyInfo.dstPort,
                        "cmd": self.proxyInfo.command,
                    })
                    if remainder:
                        self.dataReceived(remainder)
                    return
                except ValueError as e:
                    if b'\r\n' not in self._proxyBuffer and len(self._proxyBuffer) < 232:
                        return  # Need more data
                    self.log.error("Invalid PROXY protocol header: %(error)s (data: %(data)s)", {
                        "error": str(e),
                        "data": self._proxyBuffer[:32].hex(),
                    })
                    self.transport.loseConnection()
                    return

            if self.logSSLRequired:
                self.logSSLParameters()
                self.logSSLRequired = False

            self.recv(data)
        except KeyboardInterrupt:
            raise
        except ExploitError as e:
            self.log.info("Exploit detected: %(exploitInfo)s. %(parserInfo)s", {
                "exploitInfo": str(e),
                "parserInfo": e.formatLayer(len(e.layers) - 1)
            })
        except Exception as e:
            self.log.exception(e)

            if isinstance(e, ParsingError):
                self.log.error("Parser information: %(parserInfo)s", {"parserInfo": e.formatLayer(len(e.layers) - 1)})

            self.log.error("Exception occurred when receiving: %(exceptionData)s" , {"exceptionData": hexlify(data).decode()})

            raise
```

- [ ] **Step 2: Pass config to TCP layer in MITMServerFactory**

In `pyrdp/core/mitm.py`, modify `buildProtocol` (line 27-40) to set the flag:

```python
    def buildProtocol(self, addr):
        sessionID = f"{namesgenerator.get_random_name()}_{random.randrange(1000000,9999999)}"

        # mainLogger logs in a file and stdout
        mainlogger = logging.getLogger(LOGGER_NAMES.MITM_CONNECTIONS)
        mainlogger = SessionLogger(mainlogger, sessionID)

        # crawler logger only logs to a file for analysis purposes
        crawlerLogger = logging.getLogger(LOGGER_NAMES.CRAWLER)
        crawlerLogger = SessionLogger(crawlerLogger, sessionID)

        mitm = RDPMITM(mainlogger, crawlerLogger, self.config)

        protocol = mitm.getProtocol()
        if self.config.proxyProtocol:
            protocol.proxyProtocolEnabled = True

        return protocol
```

- [ ] **Step 3: Run existing tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All existing tests PASS (proxy protocol is disabled by default, no behavior change)

- [ ] **Step 4: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/layer/tcp.py pyrdp/core/mitm.py
git commit -m "feat: add PROXY protocol buffering state machine to TCP layer"
```

---

### Task 5: Client IP Resolution from PROXY Header

**Files:**
- Modify: `pyrdp/mitm/TCPMITM.py:75-88` (`onClientConnection`)

- [ ] **Step 1: Update onClientConnection to use proxyInfo**

Replace lines 75-88 of `pyrdp/mitm/TCPMITM.py`:

```python
    def onClientConnection(self):
        """
        Log the fact that a new client has connected.
        """

        # Statistics
        self.statCounter.start()

        if self.client.proxyInfo is not None:
            ip = self.client.proxyInfo.srcAddr
            port = self.client.proxyInfo.srcPort
        else:
            ip = self.client.transport.client[0]
            port = self.client.transport.client[1]

        self.state.clientIp = ip
        self.log.extra['clientIp'] = ip
        self.log.info("New client connected from %(clientIp)s:%(clientPort)i",
                      {"clientIp": ip, "clientPort": port})
```

- [ ] **Step 2: Run existing tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All existing tests PASS

- [ ] **Step 3: Run proxy protocol tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_proxy_protocol.py -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/mitm/TCPMITM.py
git commit -m "feat: resolve client IP from PROXY protocol header when available"
```

---

### Task 6: Integration Smoke Test

**Files:**
- None modified — manual verification

- [ ] **Step 1: Verify --proxy-protocol flag is recognized**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pyrdp.bin.mitm --help | grep proxy-protocol`
Expected: Shows `--proxy-protocol` in help output

- [ ] **Step 2: Verify PyRDP starts with --proxy-protocol flag**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && timeout 3 python -m pyrdp.bin.mitm 10.0.0.1:3389 --proxy-protocol 2>&1 || true`
Expected: `MITM Server listening on 0.0.0.0:3389` (or bind error if port in use — that's fine, it means it started)

- [ ] **Step 3: Run full test suite**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v && python -m pytest test/test_proxy_protocol.py -v`
Expected: All PASS

- [ ] **Step 4: Final commit with updated CLAUDE.md**

Add to the "CLI Interface" or "Entry Points" section of `CLAUDE.md`:

```markdown
### PROXY Protocol

When running behind nginx/HAProxy/AWS NLB, use `--proxy-protocol` to have PyRDP
read PROXY protocol v1/v2 headers and log the real client IP instead of the proxy's IP.
```

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add CLAUDE.md
git commit -m "docs: add PROXY protocol to CLAUDE.md"
```
