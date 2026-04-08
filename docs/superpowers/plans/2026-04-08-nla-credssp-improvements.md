# NLA/CredSSP Improvements — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix broken NLA handling in PyRDP — clean hash capture fallback (no more SSL crashes), then credential-replay CredSSP client so PyRDP can MITM sessions through NLA-requiring servers.

**Architecture:** Three layers: (1) Clean hash capture fallback — send TSRequest error after capturing NTLM hash instead of letting TLS die, (2) CredSSP client — NTLM auth, SPNEGO wrapping, TSRequest serialization, pubKeyAuth, (3) Credential-replay flow — capture plaintext creds from client, CredSSP to server, bridge sessions. Each layer works independently and falls back to the previous.

**Tech Stack:** Python 3.7+, Twisted, pycryptodome (MD4, RC4, AES, HMAC), pyasn1 (BER encoding — already a dependency), struct

**Spec:** `docs/superpowers/specs/2026-04-08-proxy-protocol-nla-improvements-design.md` — Feature 2

**Depends on:** PROXY protocol plan is independent and can be done in parallel.

---

## File Map

| File | Responsibility |
|------|---------------|
| `pyrdp/security/credssp.py` | **NEW** — `CredSSPClient` class: NTLM computation, SPNEGO, TSRequest, pubKeyAuth, TSCredentials |
| `test/test_credssp_client.py` | **NEW** — Unit tests for CredSSP client (NTLM math, serialization) |
| `test/test_nla_improvements.py` | **NEW** — Unit tests for clean hash capture fallback |
| `pyrdp/security/nla.py` | **MODIFY** — Add `disconnectCallback`, send TSRequest error after hash capture |
| `pyrdp/parser/rdp/ntlmssp.py` | **MODIFY** — Add `writeTSRequestError()` |
| `pyrdp/mitm/state.py` | **MODIFY** — Add NLA state fields |
| `pyrdp/mitm/config.py` | **MODIFY** — Add `nlaFallback` field |
| `pyrdp/mitm/cli.py` | **MODIFY** — Add `--nla-fallback` argument |
| `pyrdp/mitm/X224MITM.py` | **MODIFY** — `serverRequiresNLA` handling, fallback mode |
| `pyrdp/mitm/SecurityMITM.py` | **MODIFY** — Credential extraction callback |
| `pyrdp/mitm/RDPMITM.py` | **MODIFY** — Credential-replay orchestration, session bridging |

---

## IMPORTANT NOTE ON PLAN SCOPE

This plan covers Tasks 1-3 in detail (clean hash capture + CredSSP client core). Tasks 4-6 (credential-replay wiring, session bridging) are outlined but will need a follow-up plan with detailed code once Tasks 1-3 are verified working — the session bridging in particular requires deep integration testing against a real NLA server to validate the buffering and replay approach.

---

### Task 1: TSRequest Error Response Serialization

**Files:**
- Modify: `pyrdp/parser/rdp/ntlmssp.py`
- Create: `test/test_nla_improvements.py`

- [ ] **Step 1: Write failing test for TSRequest error serialization**

```python
# test/test_nla_improvements.py
import unittest
from io import BytesIO
from pyrdp.parser.rdp.ntlmssp import NTLMSSPParser


class TestTSRequestError(unittest.TestCase):
    def test_writeTSRequestError_contains_version_and_errorCode(self):
        """TSRequest with errorCode should be valid BER and contain the error."""
        parser = NTLMSSPParser()
        data = parser.writeTSRequestError(version=6, errorCode=0xC000006D)

        # Should be non-empty BER-encoded data
        self.assertGreater(len(data), 0)

        # First byte should be BER SEQUENCE tag (0x30)
        self.assertEqual(data[0], 0x30)

        # Should contain the error code bytes (little-endian in BER INTEGER)
        # 0xC000006D as a signed 32-bit = -1073741715
        # In BER, this is encoded as a big-endian signed integer
        self.assertIn(b'\xC0\x00\x00\x6D', data)

    def test_writeTSRequestError_version_present(self):
        """TSRequest error should contain the version number."""
        parser = NTLMSSPParser()
        data = parser.writeTSRequestError(version=6, errorCode=0xC000006D)

        # Parse it back: version [0] should be 6
        stream = BytesIO(data)
        from pyrdp.core import ber
        # Read SEQUENCE tag
        self.assertTrue(ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True))
        ber.readLength(stream)
        # Read [0] version
        self.assertTrue(ber.readContextualTag(stream, 0, True))
        version = ber.readInteger(stream)
        self.assertEqual(version, 6)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_nla_improvements.py -v`
Expected: FAIL with `AttributeError: 'NTLMSSPParser' object has no attribute 'writeTSRequestError'`

- [ ] **Step 3: Implement writeTSRequestError**

Add to `pyrdp/parser/rdp/ntlmssp.py`, at the end of the `NTLMSSPParser` class:

```python
    def writeTSRequestError(self, version: int, errorCode: int) -> bytes:
        """
        Serialize a TSRequest containing only version and errorCode.
        Used to send a clean CredSSP error back to the client after hash capture.

        TSRequest ::= SEQUENCE {
            version    [0] INTEGER,
            errorCode  [4] INTEGER
        }
        """
        stream = BytesIO()

        # Build inner content first to compute length
        inner = BytesIO()

        # [0] version
        inner.write(ber.writeContextualTag(0, 3))
        inner.write(ber.writeInteger(version))

        # [4] errorCode — encode as unsigned 32-bit big-endian
        errorBytes = errorCode.to_bytes(4, byteorder='big')
        errorTagged = BytesIO()
        errorTagged.write(ber.writeContextualTag(4, 2 + len(errorBytes)))
        errorTagged.write(ber.writeUniversalTag(ber.Tag.BER_TAG_INTEGER, False))
        errorTagged.write(ber.writeLength(len(errorBytes)))
        errorTagged.write(errorBytes)
        inner.write(errorTagged.getvalue())

        innerData = inner.getvalue()

        # SEQUENCE wrapper
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(len(innerData)))
        stream.write(innerData)

        return stream.getvalue()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_nla_improvements.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/parser/rdp/ntlmssp.py test/test_nla_improvements.py
git commit -m "feat: add TSRequest error response serialization for clean NLA hash capture"
```

---

### Task 2: Clean Hash Capture — NLAHandler Graceful Disconnect

**Files:**
- Modify: `pyrdp/security/nla.py:20-87`
- Modify: `test/test_nla_improvements.py`

- [ ] **Step 1: Write failing test for graceful disconnect after hash capture**

Add to `test/test_nla_improvements.py`:

```python
from unittest.mock import MagicMock, call
from pyrdp.security.nla import NLAHandler
from pyrdp.security import NTLMSSPState
from pyrdp.pdu import NTLMSSPChallengePDU


class TestNLAHandlerGracefulDisconnect(unittest.TestCase):
    def test_ntlm_capture_sends_error_and_disconnects(self):
        """After capturing NTLM hash, NLAHandler should send TSRequest error and call disconnect."""
        sink = MagicMock()
        state = NTLMSSPState()
        # Pre-populate a challenge so hash extraction works
        state.setMessage(NTLMSSPChallengePDU(b'\x11\x22\x33\x44\x55\x66\x77\x88'))
        disconnectCalled = MagicMock()
        log = MagicMock()

        handler = NLAHandler(sink, state, log, ntlmCapture=True, disconnectCallback=disconnectCalled)

        # Build a minimal NTLMSSP AUTHENTICATE_MESSAGE wrapped in something
        # that the handler can find via findMessage
        # The handler calls self.ntlmSSPParser.findMessage(data) then parse(data)
        # We need data containing "NTLMSSP\x00" + type 3 + fields
        from pyrdp.parser.rdp.ntlmssp import NTLMSSPParser
        # For this test, we just need the handler to detect type 3 and process it
        # We'll construct a minimal AUTHENTICATE message
        import struct
        ntlmssp = b'NTLMSSP\x00'
        msgType = struct.pack('<I', 3)  # AUTHENTICATE_MESSAGE
        # 6 security buffer fields (8 bytes each) + negotiate flags (4) + version (8) + MIC (16)
        # All zero = empty fields, which is fine for testing the disconnect behavior
        fields = b'\x00' * (6 * 8 + 4 + 8 + 16)
        authMsg = ntlmssp + msgType + fields

        # Wrap in some data (simulating TSRequest container)
        data = b'\x30\x82' + b'\x00' * 10 + authMsg

        handler.onUnknownHeader(0, data)

        # Verify: sink.sendBytes was called at least twice:
        # 1. The TSRequest error response
        # 2. (possibly the original data if forwarded — but in capture mode it should NOT forward)
        # Actually in capture mode after our change, it should send the error and NOT forward
        self.assertTrue(disconnectCalled.called, "disconnectCallback should have been called")

        # The error response should have been sent to sink
        sendCalls = sink.sendBytes.call_args_list
        self.assertGreater(len(sendCalls), 0, "Should have sent TSRequest error to sink")
        # First send should be the error TSRequest (starts with 0x30 = SEQUENCE)
        errorData = sendCalls[0][0][0]
        self.assertEqual(errorData[0], 0x30, "Error response should be a BER SEQUENCE")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_nla_improvements.py::TestNLAHandlerGracefulDisconnect -v`
Expected: FAIL — `NLAHandler.__init__` doesn't accept `disconnectCallback`

- [ ] **Step 3: Modify NLAHandler to support graceful disconnect**

Replace `pyrdp/security/nla.py` entirely:

```python
#
# This file is part of the PyRDP project.
# Copyright (C) 2021, 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
import codecs
import secrets
from typing import Callable, Optional

from pyrdp.enum import NTLMSSPMessageType
from pyrdp.layer import SegmentationObserver, IntermediateLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.logging.formatters import NTLMSSPHashFormatter
from pyrdp.parser import NTLMSSPParser
from pyrdp.pdu import NTLMSSPPDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU
from pyrdp.security import NTLMSSPState


class NLAHandler(SegmentationObserver):
    """
    Handles NLA packets by forwarding them transparently, using the onUnknownHeader event from SegmentationObserver.
    The event will be triggered when packets are sent that are neither fast-path nor TPKT (i.e: NLA).
    This also logs the hash of NLA connection attempts.
    """

    def __init__(self, sink: IntermediateLayer, state: NTLMSSPState, log: logging.LoggerAdapter,
                 ntlmCapture: bool = False, challenge: str = None,
                 disconnectCallback: Optional[Callable[[], None]] = None):
        """
        Create a new NLA Handler.
        sink: layer to forward packets to.
        state: NTLMSSPState that is shared between both the client-facing handler and the server-facing handler.
        disconnectCallback: called after hash capture to trigger clean connection teardown.
        """

        super().__init__()
        self.sink = sink
        self.ntlmSSPState = state
        self.ntlmSSPParser = NTLMSSPParser()
        self.ntlmCapture = ntlmCapture
        self.challenge = challenge
        self.log = log
        self.disconnectCallback = disconnectCallback

    def getChallenge(self):
        """
        Return configured challenge or a random 64-bit challenge
        """
        if self.challenge is None:
            challenge = b'%016x' % secrets.randbits(16 * 4)
        else:
            challenge = self.challenge
        return codecs.decode(challenge, 'hex')

    def onUnknownHeader(self, header, data: bytes):
        signatureOffset = self.ntlmSSPParser.findMessage(data)

        if signatureOffset != -1:
            message: NTLMSSPPDU = self.ntlmSSPParser.parse(data)
            self.ntlmSSPState.setMessage(message)

            if message.messageType == NTLMSSPMessageType.NEGOTIATE_MESSAGE and self.ntlmCapture:
                rawChallenge = self.getChallenge()
                self.log.debug("NTLMSSP Negotiation")
                challenge: NTLMSSPChallengePDU = NTLMSSPChallengePDU(rawChallenge)

                # There might be no state if server side connection was shutdown
                if not self.ntlmSSPState:
                    self.ntlmSSPState = NTLMSSPState()
                self.ntlmSSPState.setMessage(challenge)
                self.ntlmSSPState.challenge.serverChallenge = rawChallenge
                data = self.ntlmSSPParser.writeNTLMSSPChallenge('WINNT', rawChallenge)

            if message.messageType == NTLMSSPMessageType.AUTHENTICATE_MESSAGE:
                message: NTLMSSPAuthenticatePDU
                user = message.user
                domain = message.domain
                serverChallenge = self.ntlmSSPState.challenge.serverChallenge
                proof = message.proof
                response = message.response

                logging.getLogger(LOGGER_NAMES.NTLMSSP).info(user, domain, serverChallenge, proof, response)

                ntlmSSPHash = NTLMSSPHashFormatter.formatNTLMSSPHash(user, domain, serverChallenge, proof, response)
                self.log.info("[!] NTLMSSP Hash: %(ntlmSSPHash)s", {
                    "ntlmSSPHash": (ntlmSSPHash)
                })

                if self.ntlmCapture:
                    # Send a clean CredSSP error instead of letting the TLS tunnel die
                    errorResponse = self.ntlmSSPParser.writeTSRequestError(
                        version=6,
                        errorCode=0xC000006D  # STATUS_LOGON_FAILURE
                    )
                    self.sink.sendBytes(errorResponse)

                    if self.disconnectCallback:
                        self.disconnectCallback()
                    return  # Don't forward to server

        self.sink.sendBytes(data)
```

- [ ] **Step 4: Run tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_nla_improvements.py -v`
Expected: All PASS

- [ ] **Step 5: Run existing tests for regression**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All existing tests PASS (NLAHandler's new parameter is optional with default None)

- [ ] **Step 6: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/security/nla.py test/test_nla_improvements.py
git commit -m "feat: clean NLA hash capture — send TSRequest error instead of SSL crash"
```

---

### Task 3: Wire disconnectCallback in RDPMITM

**Files:**
- Modify: `pyrdp/mitm/RDPMITM.py:239-244`

- [ ] **Step 1: Add disconnect callback when creating NLAHandler in capture mode**

In `pyrdp/mitm/RDPMITM.py`, in `doClientTls()` method, replace lines 241-244:

```python
        if self.state.ntlmCapture:
            # We are capturing the NLA NTLMv2 hash
            self.client.segmentation.addObserver(NLAHandler(
                self.client.tcp, ntlmSSPState, self.getLog("ntlmssp"),
                ntlmCapture=True, challenge=self.state.config.sspChallenge,
                disconnectCallback=lambda: self.client.tcp.disconnect()
            ))
            return
```

- [ ] **Step 2: Run existing tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/mitm/RDPMITM.py
git commit -m "feat: wire disconnect callback into NLA capture mode for clean teardown"
```

---

### Task 4: --nla-fallback CLI Flag

**Files:**
- Modify: `pyrdp/mitm/config.py`
- Modify: `pyrdp/mitm/cli.py`

- [ ] **Step 1: Add config field**

In `pyrdp/mitm/config.py`, add after the `proxyProtocol` field:

```python
        self.nlaFallback: bool = False
        """When True, skip credential-replay CredSSP and only capture NTLM hash + disconnect cleanly."""
```

- [ ] **Step 2: Add CLI argument**

In `pyrdp/mitm/cli.py`, in `buildArgParser()`, after the `--proxy-protocol` argument:

```python
    parser.add_argument("--nla-fallback",
        help="When the server requires NLA, only capture the NTLM hash and "
             "disconnect cleanly. Do not attempt credential-replay CredSSP. "
             "Use this if you only need hashes, not full sessions.",
        action="store_true")
```

- [ ] **Step 3: Wire CLI to config**

In `pyrdp/mitm/cli.py`, in `configure()`, after `config.proxyProtocol = args.proxy_protocol`:

```python
    config.nlaFallback = args.nla_fallback
```

- [ ] **Step 4: Run tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/mitm/config.py pyrdp/mitm/cli.py
git commit -m "feat: add --nla-fallback CLI flag for hash-only NLA mode"
```

---

### Task 5: NLA State Fields

**Files:**
- Modify: `pyrdp/mitm/state.py`

- [ ] **Step 1: Add NLA state fields**

In `pyrdp/mitm/state.py`, add after line 91 (`self.ntlmCapture = False`):

```python
        self.serverRequiresNLA: bool = False
        """True if server responded with HYBRID_REQUIRED_BY_SERVER"""

        self.capturedCredentials: tuple = None
        """(username, password, domain) captured from Client Info PDU, or None"""

        self.handshakeBuffer: list = []
        """Buffered client handshake PDUs for replay to server after CredSSP"""

        self.pendingServerCredSSP: bool = False
        """True while waiting for client credentials before connecting to server"""
```

- [ ] **Step 2: Run tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m unittest discover -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/mitm/state.py
git commit -m "feat: add NLA state fields for credential-replay flow"
```

---

### Task 6: CredSSP Client — NTLM Computation Core

> **This is the critical path.** The CredSSP client is the most complex component. This task implements the NTLM math. Subsequent tasks add SPNEGO wrapping, TSRequest serialization, and the full CredSSP exchange.

**Files:**
- Create: `pyrdp/security/credssp.py`
- Create: `test/test_credssp_client.py`

- [ ] **Step 1: Write failing tests for NTLM computation (MS-NLMP test vectors)**

```python
# test/test_credssp_client.py
import unittest
from pyrdp.security.credssp import ntowfv2, computeNTLMv2Response, computeSessionBaseKey


class TestNTLMComputation(unittest.TestCase):
    """Test NTLM computation using values from MS-NLMP specification examples."""

    def test_ntowfv2(self):
        """NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user) + domain))"""
        password = "Password"
        user = "User"
        domain = "Domain"
        expected = bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f")
        result = ntowfv2(password, user, domain)
        self.assertEqual(result, expected)

    def test_computeNTLMv2Response(self):
        """Compute NTProofStr and NtChallengeResponse given known inputs."""
        responseKey = bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f")
        serverChallenge = bytes.fromhex("0123456789abcdef")
        clientChallenge = bytes.fromhex("aaaaaaaaaaaaaaaa")
        timestamp = bytes.fromhex("0000000000000000")  # simplified
        targetInfo = b""

        ntProofStr, ntChallengeResponse = computeNTLMv2Response(
            responseKey, serverChallenge, clientChallenge, timestamp, targetInfo
        )

        # NTProofStr should be 16 bytes (HMAC-MD5 output)
        self.assertEqual(len(ntProofStr), 16)
        # NtChallengeResponse = NTProofStr + temp
        self.assertTrue(ntChallengeResponse.startswith(ntProofStr))

    def test_computeSessionBaseKey(self):
        """SessionBaseKey = HMAC_MD5(responseKey, NTProofStr)"""
        responseKey = bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f")
        ntProofStr = b'\x00' * 16  # placeholder
        result = computeSessionBaseKey(responseKey, ntProofStr)
        self.assertEqual(len(result), 16)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_credssp_client.py -v`
Expected: `ModuleNotFoundError: No module named 'pyrdp.security.credssp'`

- [ ] **Step 3: Implement NTLM core computation**

```python
# pyrdp/security/credssp.py
#
# This file is part of the PyRDP project.
# Copyright (C) 2026 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
CredSSP client implementation for NLA authentication.
Implements NTLM computation (MS-NLMP) and CredSSP protocol (MS-CSSP).
"""

import hashlib
import hmac
import os
import struct

from Crypto.Cipher import ARC4, DES


def _md4(data: bytes) -> bytes:
    """Compute MD4 hash."""
    return hashlib.new('md4', data).digest()


def _hmac_md5(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-MD5."""
    return hmac.new(key, data, hashlib.md5).digest()


def ntowfv2(password: str, user: str, domain: str) -> bytes:
    """
    Compute NTOWFv2 (response key) per MS-NLMP 3.3.2.
    NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user) + domain))
    """
    ntHash = _md4(password.encode('utf-16-le'))
    userDomain = (user.upper() + domain).encode('utf-16-le')
    return _hmac_md5(ntHash, userDomain)


def computeNTLMv2Response(responseKey: bytes, serverChallenge: bytes,
                           clientChallenge: bytes, timestamp: bytes,
                           targetInfo: bytes) -> tuple:
    """
    Compute NTLMv2 response per MS-NLMP 3.3.2.
    Returns (NTProofStr, NtChallengeResponse).
    """
    # temp = Responserversion(1) + HiResponserversion(1) + Z(6) + Time(8) + ClientChallenge(8) + Z(4) + TargetInfo + Z(4)
    temp = (
        b'\x01\x01'          # Responserversion + HiResponserversion
        + b'\x00' * 6        # Z(6)
        + timestamp           # Time (FILETIME, 8 bytes)
        + clientChallenge     # ClientChallenge (8 bytes)
        + b'\x00' * 4        # Z(4)
        + targetInfo          # ServerName (TargetInfo AV_PAIRs)
        + b'\x00' * 4        # Z(4)
    )

    ntProofStr = _hmac_md5(responseKey, serverChallenge + temp)
    ntChallengeResponse = ntProofStr + temp

    return ntProofStr, ntChallengeResponse


def computeSessionBaseKey(responseKey: bytes, ntProofStr: bytes) -> bytes:
    """
    Compute SessionBaseKey per MS-NLMP 3.3.2.
    SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    """
    return _hmac_md5(responseKey, ntProofStr)


def computeKeyExchangeKey(sessionBaseKey: bytes) -> bytes:
    """
    With NTLMSSP_NEGOTIATE_KEY_EXCH, KeyExchangeKey = SessionBaseKey.
    (For NTLMv2, this is always the case.)
    """
    return sessionBaseKey


def exportedSessionKey(keyExchangeKey: bytes) -> tuple:
    """
    Generate ExportedSessionKey and EncryptedRandomSessionKey.
    ExportedSessionKey = random(16)
    EncryptedRandomSessionKey = RC4(KeyExchangeKey, ExportedSessionKey)
    Returns (ExportedSessionKey, EncryptedRandomSessionKey).
    """
    exported = os.urandom(16)
    cipher = ARC4.new(keyExchangeKey)
    encrypted = cipher.encrypt(exported)
    return exported, encrypted


def computeSignKey(exportedKey: bytes, clientToServer: bool = True) -> bytes:
    """Compute SignKey per MS-NLMP 3.4.4."""
    if clientToServer:
        magic = b"session key to client-to-server signing key magic constant\x00"
    else:
        magic = b"session key to server-to-client signing key magic constant\x00"
    return hashlib.md5(exportedKey + magic).digest()


def computeSealKey(exportedKey: bytes, clientToServer: bool = True) -> bytes:
    """Compute SealKey per MS-NLMP 3.4.4."""
    if clientToServer:
        magic = b"session key to client-to-server sealing key magic constant\x00"
    else:
        magic = b"session key to server-to-client sealing key magic constant\x00"
    return hashlib.md5(exportedKey + magic).digest()
```

- [ ] **Step 4: Run tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_credssp_client.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/security/credssp.py test/test_credssp_client.py
git commit -m "feat: add NTLM computation core for CredSSP client (NTOWFv2, NTLMv2Response, session keys)"
```

---

### Task 7: CredSSP Client — GSS_WrapEx and pubKeyAuth

> Adds message signing/encryption (GSS_WrapEx) and pubKeyAuth computation. These are needed to construct the final AUTHENTICATE TSRequest.

**Files:**
- Modify: `pyrdp/security/credssp.py`
- Modify: `test/test_credssp_client.py`

- [ ] **Step 1: Write failing tests**

Add to `test/test_credssp_client.py`:

```python
from pyrdp.security.credssp import gssWrapEx, computePubKeyAuth


class TestGSSWrapEx(unittest.TestCase):
    def test_gssWrapEx_output_format(self):
        """GSS_WrapEx output = Version(4) + Checksum(8) + SeqNum(4) + EncryptedMessage"""
        key = os.urandom(16)
        sealKey = os.urandom(16)
        signKey = os.urandom(16)
        message = b"test message"
        seqNum = 0

        result = gssWrapEx(signKey, sealKey, seqNum, message)

        # Version (4 bytes) = 0x00000001
        self.assertEqual(result[:4], b'\x01\x00\x00\x00')
        # Total = 4 (ver) + 8 (checksum) + 4 (seqnum) + len(encrypted)
        self.assertEqual(len(result), 4 + 8 + 4 + len(message))

    def test_computePubKeyAuth_v2(self):
        """pubKeyAuth for version 2-4: encrypt(serverPublicKey)"""
        exportedKey = os.urandom(16)
        serverPubKey = os.urandom(256)  # fake public key
        result = computePubKeyAuth(exportedKey, serverPubKey, version=2)
        self.assertGreater(len(result), 0)

    def test_computePubKeyAuth_v5(self):
        """pubKeyAuth for version 5+: encrypt(SHA256(magic + nonce + serverPubKey))"""
        exportedKey = os.urandom(16)
        serverPubKey = os.urandom(256)
        nonce = os.urandom(32)
        result = computePubKeyAuth(exportedKey, serverPubKey, version=5, nonce=nonce)
        self.assertGreater(len(result), 0)


import os
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_credssp_client.py::TestGSSWrapEx -v`
Expected: FAIL — `cannot import name 'gssWrapEx'`

- [ ] **Step 3: Implement GSS_WrapEx and pubKeyAuth**

Add to `pyrdp/security/credssp.py`:

```python
def gssWrapEx(signKey: bytes, sealKey: bytes, seqNum: int, message: bytes) -> bytes:
    """
    GSS_WrapEx: sign and encrypt a message per MS-NLMP 3.4.4.
    Output: Version(4) + Checksum(8) + SeqNum(4) + EncryptedMessage
    """
    # SeqNum as little-endian 4 bytes
    seqNumBytes = struct.pack('<I', seqNum)

    # Encrypt the message with RC4 using the seal key
    cipher = ARC4.new(sealKey)
    encryptedMessage = cipher.encrypt(message)

    # Compute HMAC_MD5 signature
    # Checksum = HMAC_MD5(SignKey, SeqNum + Message)[:8]
    checksum = _hmac_md5(signKey, seqNumBytes + message)[:8]

    # Encrypt the checksum with RC4 using the seal key
    cipher2 = ARC4.new(sealKey)
    encryptedChecksum = cipher2.encrypt(checksum)

    # Version = 0x00000001
    version = struct.pack('<I', 1)

    return version + encryptedChecksum + seqNumBytes + encryptedMessage


def computePubKeyAuth(exportedSessionKey: bytes, serverPublicKey: bytes,
                       version: int, nonce: bytes = None) -> bytes:
    """
    Compute pubKeyAuth for CredSSP TSRequest.
    version 2-4: encrypt(serverPublicKey)
    version 5+: encrypt(SHA256("CredSSP Client-To-Server Binding Hash\0" + nonce + serverPublicKey))
    """
    signKey = computeSignKey(exportedSessionKey, clientToServer=True)
    sealKey = computeSealKey(exportedSessionKey, clientToServer=True)

    if version >= 5:
        if nonce is None:
            nonce = os.urandom(32)
        magic = b"CredSSP Client-To-Server Binding Hash\x00"
        hashInput = magic + nonce + serverPublicKey
        message = hashlib.sha256(hashInput).digest()
    else:
        message = serverPublicKey

    return gssWrapEx(signKey, sealKey, 0, message)
```

- [ ] **Step 4: Run tests**

Run: `cd F:/laboratory/Honeypot-General/pyrdp/pyrdp && python -m pytest test/test_credssp_client.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp
git add pyrdp/security/credssp.py test/test_credssp_client.py
git commit -m "feat: add GSS_WrapEx signing/encryption and pubKeyAuth for CredSSP client"
```

---

### Tasks 8-12: SPNEGO Wrapping, TSRequest Serialization, CredSSP Exchange, Credential-Replay Flow, Session Bridging

> **These tasks require detailed implementation against a real NLA server for validation.** The code is architecturally complex (async Twisted integration, PDU buffering, session state synchronization). Rather than writing speculative code now, these tasks should be planned in a follow-up after Tasks 1-7 are verified working.

**Task 8: SPNEGO NegTokenInit/NegTokenResp wrapping**
- Wrap NTLMSSP messages in SPNEGO tokens (ASN.1/BER)
- Use pyasn1 (already a PyRDP dependency)
- Files: `pyrdp/security/credssp.py`, `test/test_credssp_client.py`

**Task 9: TSRequest serialization for full CredSSP exchange**
- Build complete TSRequest PDUs with negoTokens, pubKeyAuth, clientNonce, authInfo
- Extend existing `writeNTLMSSPTSRequest` in `pyrdp/parser/rdp/ntlmssp.py`
- Files: `pyrdp/parser/rdp/ntlmssp.py`, `pyrdp/security/credssp.py`

**Task 10: CredSSPClient full exchange**
- Orchestrate the 5-step CredSSP message exchange over a Twisted TCP+TLS connection
- Handle version negotiation (start at v2, adapt to server's response)
- Files: `pyrdp/security/credssp.py`

**Task 11: Credential-replay flow in RDPMITM**
- Modify `X224MITM.onConnectionConfirm` for `serverRequiresNLA` state
- Add `SecurityMITM` callback to extract credentials from Client Info PDU
- Add `RDPMITM.onCredentialsCaptured` → `performServerCredSSP`
- Files: `pyrdp/mitm/X224MITM.py`, `pyrdp/mitm/SecurityMITM.py`, `pyrdp/mitm/RDPMITM.py`

**Task 12: Session bridging**
- Buffer client handshake PDUs during Phase 1
- Replay to server after CredSSP completes
- Handle MCS Connect Response adaptation
- Files: `pyrdp/mitm/RDPMITM.py`, `pyrdp/mitm/state.py`

---

## Summary

| Task | Status | Description |
|------|--------|-------------|
| 1 | Ready | TSRequest error response serialization |
| 2 | Ready | NLAHandler graceful disconnect after hash capture |
| 3 | Ready | Wire disconnectCallback in RDPMITM |
| 4 | Ready | --nla-fallback CLI flag |
| 5 | Ready | NLA state fields |
| 6 | Ready | CredSSP client NTLM computation core |
| 7 | Ready | GSS_WrapEx and pubKeyAuth |
| 8-12 | Outlined | SPNEGO, TSRequest, CredSSP exchange, credential-replay, session bridging — follow-up plan after 1-7 verified |
