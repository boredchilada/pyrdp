# PyRDP Proxy Protocol & NLA Improvements Design

**Date:** 2026-04-08
**Status:** Draft

---

## Problem Statement

PyRDP has two operational gaps when deployed as a honeypot or MITM tool:

1. **No PROXY protocol support:** When PyRDP sits behind nginx (TCP stream proxy) or AWS NLB, it sees the proxy's IP as the client IP, not the real attacker's IP. This makes honeypot logs useless for attribution.

2. **Broken NLA handling:** When the target RDP server requires NLA (Network Level Authentication), PyRDP captures the NTLM hash but then the connection dies with SSL errors (`unsupported protocol`, `unexpected eof while reading`). The RDP client sees error 0x904. This produces noisy logs and no usable session.

---

## Scope

Two features, designed to work independently:

- **Feature 1:** PROXY protocol v1/v2 inbound support
- **Feature 2:** NLA/CredSSP support — credential-replay CredSSP client, clean hash capture fallback, version downgrade attempt

### Out of Scope

- Outbound proxy support (SOCKS5/HTTP CONNECT for PyRDP-to-server connections)
- Multi-target routing within a single PyRDP instance
- RDP fingerprint masking proxy (separate spec planned)

---

## Technical Background

### Current Connection Flow (Non-NLA)

```
Client                          PyRDP                           Server
  │                               │                               │
  ├── X224 ConnReq (TLS+NLA) ──> │                               │
  │                               ├── X224 ConnReq (TLS only) ──>│  ← downgrade strips NLA
  │                               │<── X224 ConnConfirm (TLS) ───┤
  │<── X224 ConnConfirm (TLS) ───┤                               │
  │                               │                               │
  │<══════ TLS Handshake ════════>│<══════ TLS Handshake ════════>│
  │                               │                               │
  │── MCS Connect Initial ──────>│── MCS Connect Initial ──────> │
  │<── MCS Connect Response ─────│<── MCS Connect Response ──────│
  │── Erect Domain / Attach ────>│── Erect Domain / Attach ─────>│
  │── Channel Join ─────────────>│── Channel Join ──────────────>│
  │── Security Exchange ────────>│── Security Exchange ─────────>│
  │── Client Info PDU ──────────>│── Client Info PDU ───────────>│  ← PyRDP captures
  │   (plaintext user+pass)      │   (plaintext user+pass)       │    credentials HERE
  │<── Server License ───────────│<── Server License ────────────│
  │<── Capability Exchange ──────│<── Capability Exchange ───────│
  │                               │                               │
  │══════════ RDP Session (MITM'd) ══════════════════════════════>│
```

This works when the server accepts TLS-only. PyRDP sees everything in plaintext.

### Current Connection Flow (NLA Required — Broken)

```
Client                          PyRDP                           Server
  │                               │                               │
  ├── X224 ConnReq (TLS+NLA) ──> │                               │
  │                               ├── X224 ConnReq (TLS only) ──>│
  │                               │<── HYBRID_REQUIRED ──────────┤  ← server demands NLA
  │                               │                               │
  │   ┌─ PyRDP enters ntlmCapture mode ─┐                        │
  │   │ Disconnects from server          │                        │
  │   │ Replays ConnReq WITH NLA enabled │                        │
  │   │ Reconnects to server             │                        │
  │   └─────────────────────────────────-┘                        │
  │                               │                               │
  │<══════ TLS Handshake ════════>│<══════ TLS Handshake ════════>│
  │                               │                               │
  │── CredSSP: NTLM NEGOTIATE ─>│   (client-side NLA handler     │
  │<── CredSSP: FAKE CHALLENGE ──│    generates fake challenge)   │
  │── CredSSP: AUTHENTICATE ────>│                               │
  │   (NTLM hash captured ✓)     │                               │
  │                               │                               │
  │   ... silence ...             │   (no valid pubKeyAuth        │
  │   ... TLS tunnel dies ...     │    response sent back)        │
  │                               │                               │
  │<── SSL ERROR / TIMEOUT ──────│                               │
  │   "Error 0x904"               │                               │
```

The hash IS captured, but the connection dies because PyRDP can't complete CredSSP.

### Why CredSSP Relay (Packet Forwarding) Is Impossible

CredSSP includes a `pubKeyAuth` field — TLS channel binding. The client encrypts the server's TLS public key using the NTLM session key (derived from the user's password). In a MITM with two TLS tunnels:

- Client encrypts **PyRDP's** TLS public key (that's what it sees)
- Server expects **its own** TLS public key
- Mismatch → auth failure
- PyRDP can't re-encrypt because it doesn't have the NTLM session key (derived from the password hash it doesn't possess during the CredSSP exchange)

CVE-2018-0886 (pre-March 2018) allowed dropping `pubKeyAuth`, but patched in CredSSP v5+.

### Why Credential Replay DOES Work

PyRDP doesn't need to relay CredSSP. It can be a **CredSSP client** on the server side:

1. Client side: TLS-only downgrade works → client sends plaintext password in Client Info PDU
2. PyRDP captures the plaintext username + password + domain
3. Server side: PyRDP performs CredSSP authentication using the captured credentials
4. PyRDP HAS the plaintext password → can compute NTLM session key → can construct valid `pubKeyAuth`

No relay needed. Independent CredSSP on the server side with known credentials.

---

## Feature 1: PROXY Protocol Support

### Overview

Add a `--proxy-protocol` CLI flag. When enabled, PyRDP reads a PROXY protocol header from the first bytes of each new TCP connection before passing data to the RDP layer stack. The real client IP/port from the header replaces the transport peer address in all logging and state.

### Protocol Specifications

#### PROXY Protocol v1 (Text)

```
PROXY TCP4 192.168.1.100 10.0.0.1 56324 3389\r\n
PROXY TCP6 2001:db8::1 2001:db8::2 56324 3389\r\n
PROXY UNKNOWN\r\n
```

- ASCII text, single line, terminated by `\r\n`
- Maximum 107 bytes
- Fields separated by single space: `PROXY <proto> <src_ip> <dst_ip> <src_port> <dst_port>`
- `proto` is one of: `TCP4`, `TCP6`, `UNKNOWN`
- `UNKNOWN` may omit address fields entirely

#### PROXY Protocol v2 (Binary)

```
Offset  Size     Field
──────  ──────   ─────────────────────────────────────────────
0-11    12 B     Signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
12      1 B      Version (high nibble, must be 0x2) | Command (low nibble)
                   Command: 0x0 = LOCAL (health check), 0x1 = PROXY
13      1 B      Address family (high nibble) | Transport protocol (low nibble)
                   Family:    0x1 = AF_INET, 0x2 = AF_INET6
                   Transport: 0x1 = STREAM (TCP)
14-15   2 B      Length (big-endian uint16) of address data + TLV extensions
16+     var      Address data:
                   IPv4/TCP (12 B): src_addr(4) + dst_addr(4) + src_port(2) + dst_port(2)
                   IPv6/TCP (36 B): src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2)
                 Followed by optional TLV extensions (type:1 + length:2 + value:N)
```

Common v2 byte values:
- `0x21` at offset 12 = v2, PROXY command
- `0x11` at offset 13 = IPv4 + TCP
- `0x21` at offset 13 = IPv6 + TCP

TLV types (parsed but only logged):
- `0x01` PP2_TYPE_ALPN
- `0x02` PP2_TYPE_AUTHORITY (SNI)
- `0x20` PP2_TYPE_SSL
- `0xEA` PP2_TYPE_AWS (AWS NLB VPC endpoint info)

### Auto-Detection Logic

```python
def detectVersion(data: bytes) -> str:
    V2_SIGNATURE = b'\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A'
    if len(data) >= 12 and data[:12] == V2_SIGNATURE:
        return 'v2'
    elif len(data) >= 5 and data[:5] == b'PROXY':
        return 'v1'
    else:
        return 'invalid'
```

When `--proxy-protocol` is enabled, a valid header is **mandatory**. Connections without one are rejected.

### Data Flow

```
┌──────────────────────────────────────────────────────────┐
│ TwistedTCPLayer                                          │
│                                                          │
│  State: AWAITING_PROXY_HEADER                            │
│  ┌──────────────────────────────────────┐                │
│  │ dataReceived(data)                   │                │
│  │   buffer += data                     │                │
│  │   if canParseHeader(buffer):         │                │
│  │     header = parseProxyProtocol()    │                │
│  │     self.proxyInfo = header          │                │
│  │     remainder = buffer[header.size:] │                │
│  │     state = NORMAL_OPERATION         │                │
│  │     if remainder:                    │                │
│  │       self.recv(remainder)           │                │
│  └──────────────────────────────────────┘                │
│                                                          │
│  State: NORMAL_OPERATION                                 │
│  ┌──────────────────────────────────────┐                │
│  │ dataReceived(data)                   │                │
│  │   self.recv(data)  # normal path     │                │
│  └──────────────────────────────────────┘                │
└──────────────────────────────────────────────────────────┘
```

Buffering is bounded: v1 max 107 bytes, v2 fixed 16-byte header tells exact remaining length. If buffer exceeds 232 bytes (max v2 with IPv6 + generous TLV) without a valid header, reject.

### Client IP Resolution

In `TCPMITM.onClientConnection()`:

```python
# Current code (line 83):
ip = self.client.transport.client[0]
port = self.client.transport.client[1]

# New code:
if self.client.proxyInfo is not None:
    ip = self.client.proxyInfo.srcAddr
    port = self.client.proxyInfo.srcPort
else:
    ip = self.client.transport.client[0]
    port = self.client.transport.client[1]
```

This single change point propagates to all logging because `state.clientIp` is set here and all loggers reference it.

### CLI Interface

```
pyrdp-mitm 192.168.1.100:3389 --proxy-protocol
```

New argument in `buildArgParser()`:
```python
parser.add_argument("--proxy-protocol",
    help="Enable PROXY protocol v1/v2 support. Use when PyRDP is behind "
         "nginx, HAProxy, or AWS NLB. The proxy must send a PROXY protocol "
         "header so PyRDP can see the real client IP.",
    action="store_true")
```

### Nginx Configuration Example

```nginx
stream {
    upstream pyrdp_backend {
        server 10.0.0.5:3389;
    }

    server {
        listen 3389;
        proxy_pass pyrdp_backend;
        proxy_protocol on;   # prepends PROXY protocol header to upstream
    }
}
```

### Error Handling

| Condition | Action |
|-----------|--------|
| `--proxy-protocol` enabled, first bytes don't match v1 or v2 | Log error with hex dump of first 16 bytes, close connection |
| Header is malformed (bad length, invalid IP, truncated) | Log error with details, close connection |
| v2 header with LOCAL command (health check) | Log debug message, close connection (no RDP session) |
| `--proxy-protocol` NOT enabled | No change — direct connections work as before |
| Buffer timeout (no complete header within 5 seconds) | Log error, close connection |

### Files Changed

| File | Change |
|------|--------|
| `pyrdp/core/proxy_protocol.py` | **NEW** — `ProxyProtocolHeader` dataclass, v1/v2 parsers, auto-detect |
| `pyrdp/layer/tcp.py` | Add `proxyProtocolEnabled` flag, buffering state machine in `dataReceived()`, `proxyInfo` attribute |
| `pyrdp/mitm/TCPMITM.py` | Use `proxyInfo` for client IP/port in `onClientConnection()` |
| `pyrdp/mitm/cli.py` | Add `--proxy-protocol` argument |
| `pyrdp/mitm/config.py` | Add `proxyProtocol: bool = False` to `MITMConfig` |
| `pyrdp/core/mitm.py` | Pass `proxyProtocol` flag from config to `TwistedTCPLayer` during connection setup |
| `test/test_proxy_protocol.py` | **NEW** — unit tests |

---

## Feature 2: NLA/CredSSP Support

### Strategy Overview

Three-layer approach with automatic fallback:

```
┌─────────────────────────────────────────────────────────────────┐
│  Server requires NLA?                                           │
│  ├── NO → Standard TLS-only MITM (existing behavior, no change)│
│  └── YES ↓                                                      │
│                                                                 │
│  Can client be downgraded to TLS-only?                          │
│  ├── YES → PRIMARY: Credential-Replay CredSSP Client (2A)      │
│  │         Capture plaintext creds from client, then do CredSSP │
│  │         to server ourselves. Full session MITM.              │
│  │         ├── CredSSP succeeds → Session bridged ✓             │
│  │         └── CredSSP fails → Fall through ↓                   │
│  │                                                              │
│  └── NO (client insists on NLA) ↓                               │
│                                                                 │
│  Is --nla-fallback set?                                         │
│  ├── YES → FALLBACK: Clean Hash Capture (2C)                   │
│  │         Capture NTLM hash, send CredSSP error, close cleanly│
│  └── NO → Attempt CredSSP version downgrade (2B)               │
│           ├── Unpatched server → May succeed ✓                  │
│           └── Patched server → Clean Hash Capture (2C)          │
└─────────────────────────────────────────────────────────────────┘
```

### 2A: Credential-Replay CredSSP Client (Primary)

#### Connection Flow

```
Client                          PyRDP                           Server
  │                               │                               │
  │── X224 ConnReq (TLS+NLA) ──>│                               │
  │                               │── X224 ConnReq (TLS only) ──>│
  │                               │<── HYBRID_REQUIRED ──────────┤
  │                               │                               │
  │                     ┌─────────┴──────────┐                    │
  │                     │ state.serverNLA=True│                    │
  │                     │ Disconnect server   │                    │
  │                     └─────────┬──────────┘                    │
  │                               │                               │
  │<── X224 ConnConfirm (TLS) ───┤  ← tell client TLS-only is fine
  │                               │
  │<══════ TLS Handshake ════════>│  ← client-side TLS only
  │                               │
  │── MCS Connect Initial ──────>│  ← PyRDP buffers these PDUs
  │<── MCS Connect Response ─────│    (responds from cache/defaults)
  │── Erect Domain / Attach ────>│
  │── Channel Join ─────────────>│
  │── Security Exchange ────────>│
  │── Client Info PDU ──────────>│  ← *** PLAINTEXT CREDS CAPTURED ***
  │                               │
  │                     ┌─────────┴──────────────────────────┐
  │                     │ Got creds! Now connect to server.  │
  │                     │                                    │
  │                     │ 1. TCP connect to server           │
  │                     │ 2. X224 ConnReq (TLS + NLA)        │
  │                     │ 3. X224 ConnConfirm (NLA)          │
  │                     │ 4. TLS handshake with server       │
  │                     │ 5. CredSSP exchange:               │
  │                     │    a. NEGOTIATE_MESSAGE             │
  │                     │    b. Receive CHALLENGE_MESSAGE     │
  │                     │    c. Compute NTLMv2 response       │
  │                     │       (we have the password!)       │
  │                     │    d. Compute session key           │
  │                     │    e. Encrypt server TLS pubkey     │
  │                     │       → valid pubKeyAuth            │
  │                     │    f. Send AUTHENTICATE + pubKeyAuth│
  │                     │    g. Receive server confirmation   │
  │                     │    h. Send TSCredentials            │
  │                     │ 6. CredSSP complete ✓               │
  │                     └─────────┬──────────────────────────┘
  │                               │                               │
  │                               │── MCS Connect Initial ──────>│  ← replay buffered
  │                               │<── MCS Connect Response ─────│
  │                               │── Erect Domain / Attach ────>│
  │                               │── Channel Join ─────────────>│
  │                               │── Client Info PDU ──────────>│
  │                               │<── Server License ───────────│
  │<── Server License ───────────│                               │
  │                               │                               │
  │══════════ RDP Session (fully MITM'd) ═══════════════════════>│
```

#### CredSSP Client Implementation

The CredSSP client performs NTLM authentication inside SPNEGO tokens, wrapped in TSRequest PDUs, over the server-side TLS tunnel.

**NTLM Computation Chain:**

```
password (plaintext, captured from client)
    │
    ▼
NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user) + domain))
    │                                         ← "response key"
    ▼
ServerChallenge (8 bytes, from server's CHALLENGE_MESSAGE)
ClientChallenge (8 bytes, random)
Timestamp (8 bytes, FILETIME)
TargetInfo (from server's CHALLENGE_MESSAGE AV_PAIRs)
    │
    ▼
temp = 0x01 0x01 0x00×6 + Timestamp + ClientChallenge + 0x00×4 + TargetInfo + 0x00×4
NTProofStr = HMAC_MD5(NTOWFv2, ServerChallenge + temp)
NtChallengeResponse = NTProofStr + temp
    │
    ▼
SessionBaseKey = HMAC_MD5(NTOWFv2, NTProofStr)
    │
    ▼  (if NTLMSSP_NEGOTIATE_KEY_EXCH flag set)
ExportedSessionKey = random(16)
EncryptedRandomSessionKey = RC4(SessionBaseKey, ExportedSessionKey)
    │
    ▼
SignKey = MD5(ExportedSessionKey + "session key to client-to-server signing key magic constant\0")
SealKey = MD5(ExportedSessionKey + "session key to client-to-server sealing key magic constant\0")
```

**pubKeyAuth Computation:**

```
ServerTLSPublicKey = DER-encoded SubjectPublicKeyInfo from server's X.509 cert

If CredSSP version 2-4:
    pubKeyAuth = GSS_WrapEx(ExportedSessionKey, ServerTLSPublicKey)

If CredSSP version 5-6:
    Nonce = random(32)  ← sent in TSRequest.clientNonce
    HashInput = "CredSSP Client-To-Server Binding Hash\0" + Nonce + ServerTLSPublicKey
    pubKeyAuth = GSS_WrapEx(ExportedSessionKey, SHA256(HashInput))
```

`GSS_WrapEx` uses the negotiated seal key (RC4 or AES, depending on NTLM flags) to encrypt, and the sign key to generate a MAC signature. The output format is: `Version(4) + Checksum(8) + SeqNum(4) + EncryptedMessage`.

**TSRequest PDU Serialization (BER/ASN.1):**

```asn1
TSRequest ::= SEQUENCE {
    version    [0] INTEGER,              -- CredSSP version (2-6)
    negoTokens [1] NegoData  OPTIONAL,   -- SPNEGO tokens wrapping NTLMSSP
    authInfo   [2] OCTET STRING OPTIONAL,-- Encrypted TSCredentials
    pubKeyAuth [3] OCTET STRING OPTIONAL,-- Encrypted server public key
    errorCode  [4] INTEGER OPTIONAL,     -- NTSTATUS on failure
    clientNonce [5] OCTET STRING OPTIONAL -- 32 bytes, version 5+ only
}
```

**SPNEGO Wrapping:**

NTLMSSP messages are wrapped in SPNEGO tokens:
- First message (NEGOTIATE): `NegTokenInit { mechTypes: [NTLMSSP OID], mechToken: NEGOTIATE_MESSAGE }`
- Subsequent messages (AUTHENTICATE): `NegTokenResp { responseToken: AUTHENTICATE_MESSAGE }`

SPNEGO itself is wrapped in the TSRequest.negoTokens field.

**TSCredentials (sent after pubKeyAuth confirmed):**

```asn1
TSCredentials ::= SEQUENCE {
    credType    [0] INTEGER,  -- 1 = password
    credentials [1] OCTET STRING  -- DER-encoded TSPasswordCreds
}

TSPasswordCreds ::= SEQUENCE {
    domainName [0] OCTET STRING,  -- UTF-16LE
    userName   [1] OCTET STRING,  -- UTF-16LE
    password   [2] OCTET STRING   -- UTF-16LE
}
```

Encrypted with `GSS_WrapEx` using the session key.

**Message Exchange Sequence:**

```
Step  Direction      TSRequest contents
────  ─────────────  ──────────────────────────────────────────────
1     PyRDP→Server   version=2, negoTokens=[NegTokenInit(NTLM NEGOTIATE)]
2     Server→PyRDP   version=N, negoTokens=[NegTokenResp(NTLM CHALLENGE)]
3     PyRDP→Server   version=2, negoTokens=[NegTokenResp(NTLM AUTH)],
                     pubKeyAuth=encrypted(serverPubKey),
                     clientNonce=random(32) (if version≥5)
4     Server→PyRDP   version=N, pubKeyAuth=encrypted(confirmation)
5     PyRDP→Server   version=2, authInfo=encrypted(TSCredentials)
```

#### Session Bridging

After CredSSP completes on the server side, PyRDP must synchronize both sides of the connection. The client is already past the MCS handshake; the server is just starting it.

**What PyRDP buffers during Phase 1 (client handshake):**

| PDU | Action |
|-----|--------|
| MCS Connect Initial | Buffer raw bytes |
| MCS Erect Domain Request | Buffer raw bytes |
| MCS Attach User Request | Buffer raw bytes |
| MCS Channel Join Requests | Buffer raw bytes (one per channel) |
| Security Exchange | Buffer raw bytes |
| Client Info PDU | Buffer raw bytes + extract credentials |

**Replay strategy after CredSSP (Phase 3):**

1. Send buffered MCS Connect Initial to server
2. Wait for server's MCS Connect Response → forward to client
3. Send buffered Erect Domain, Attach User → wait for server confirms → forward to client
4. Send buffered Channel Joins → wait for server confirms → forward to client
5. Send buffered Security Exchange and Client Info PDU to server
6. Wait for Server License → forward to client
7. From this point: standard MITM bridging (both sides in sync)

**Edge case — MCS Connect Response mismatch:**

The server's MCS Connect Response may differ from what PyRDP sent to the client during Phase 1 (PyRDP had to respond without the real server). Specifically, the server may offer different channels or capabilities.

**Mitigation:** During Phase 1, PyRDP generates a synthetic MCS Connect Response based on the client's request, using conservative defaults. During Phase 3, if the real server's response differs significantly, PyRDP adapts the channel mapping. If critical mismatches occur (e.g., server doesn't support a channel the client expects), log a warning and continue best-effort.

#### RDPMITM Changes

**New state fields in `state.py`:**

```python
self.serverRequiresNLA: bool = False
"""True if server responded with HYBRID_REQUIRED_BY_SERVER"""

self.capturedCredentials: Optional[Tuple[str, str, str]] = None
"""(username, password, domain) captured from Client Info PDU"""

self.handshakeBuffer: list = []
"""Buffered client handshake PDUs for replay to server after CredSSP"""

self.pendingServerCredSSP: bool = False
"""True while waiting for client credentials before connecting to server"""
```

**Modified flow in `RDPMITM.py`:**

Current `connectToServer()` (line 188-218):
- Connects to server immediately
- Waits for server connection
- Connects to attacker

New `connectToServer()`:
- Connects to server
- If server returns `HYBRID_REQUIRED`, sets `state.serverRequiresNLA = True`
- Disconnects from server
- Continues client handshake (TLS-only)
- Does NOT connect attacker yet (wait for full session)

New method `onCredentialsCaptured(username, password, domain)`:
- Called by SecurityMITM when Client Info PDU is parsed
- Stores credentials in state
- Calls `performServerCredSSP()`

New method `performServerCredSSP()`:
- Reconnects to server (TCP + X224 with NLA + TLS)
- Instantiates `CredSSPClient` with captured credentials
- Runs CredSSP authentication
- On success: calls `replayBufferedHandshake()`
- On failure: logs error, closes both connections cleanly

New method `replayBufferedHandshake()`:
- Sends buffered PDUs to server in order
- Wires up standard MITM observers
- Transitions to normal MITM operation

**Modified `SecurityMITM.py`:**

Add credential extraction callback. Currently SecurityMITM processes Client Info PDU for logging. Add a hook:

```python
# In SecurityMITM, when Client Info PDU is received:
if self.state.serverRequiresNLA and self.credentialCallback:
    self.credentialCallback(
        clientInfoPDU.username,
        clientInfoPDU.password,
        clientInfoPDU.domain
    )
```

**Modified `X224MITM.py`:**

Update `onConnectionConfirm()` handling of `HYBRID_REQUIRED_BY_SERVER`:

Current (line 126-145):
- Either redirects to NLA redirection host, or enters ntlmCapture mode

New:
- If `config.nlaFallback`: go straight to clean hash capture (2C)
- Else: set `state.serverRequiresNLA = True`, disconnect from server, continue client handshake

### 2B: CredSSP Version Downgrade (Opportunistic)

Built into the CredSSP client. When `CredSSPClient` connects to the server:

1. Send TSRequest with `version = 2` (minimum)
2. Server responds with its maximum supported version
3. If server accepts version 2-4: use simple pubKeyAuth (just encrypted public key, no nonce)
4. If server demands version 5+: use nonce-based pubKeyAuth (SHA256 hash with magic strings)

Both paths are implemented in the CredSSP client. The version downgrade is automatic — not a separate mode.

**On unpatched servers (pre-CVE-2018-0886):** Version 2-4 may bypass pubKeyAuth validation entirely, which is a bonus but not relied upon since we can construct valid pubKeyAuth anyway (we have the password).

### 2C: Clean Hash Capture (Last-Resort Fallback)

**Triggers when:**
- `--nla-fallback` flag is set (skip credential-replay entirely)
- Client insists on NLA and cannot be downgraded (Restricted Admin Mode, or client remembers NLA from prior connection)
- Credential-replay CredSSP fails (server rejects captured creds)

**Current behavior:** Connection hangs → SSL crashes → noisy logs.

**New behavior:**

```
Client                          PyRDP
  │                               │
  │── CredSSP: NTLM NEGOTIATE ─>│
  │<── CredSSP: CHALLENGE ───────│  (fake challenge)
  │── CredSSP: AUTHENTICATE ────>│
  │   (NTLM hash captured ✓)     │
  │                               │
  │<── TSRequest(errorCode=      │  ← NEW: proper error response
  │     STATUS_LOGON_FAILURE)    │
  │                               │
  │<── X224 Disconnect Request ──│  ← NEW: clean disconnect
  │                               │
  │   Client shows:               │
  │   "Logon attempt failed"     │  ← instead of cryptic 0x904
```

**Changes to `nla.py` — `NLAHandler`:**

After capturing AUTHENTICATE_MESSAGE in ntlmCapture mode (current line 71-84):

```python
if message.messageType == NTLMSSPMessageType.AUTHENTICATE_MESSAGE:
    # ... existing hash capture code ...

    if self.ntlmCapture:
        # NEW: Send CredSSP error and close cleanly
        errorResponse = self.ntlmSSPParser.writeTSRequestError(
            version=6,
            errorCode=0xC000006D  # STATUS_LOGON_FAILURE
        )
        self.sink.sendBytes(errorResponse)

        if self.disconnectCallback:
            self.disconnectCallback()
        return  # Don't forward to server
```

**Changes to `parser/rdp/ntlmssp.py`:**

New method:
```python
def writeTSRequestError(self, version: int, errorCode: int) -> bytes:
    """Serialize a TSRequest containing only version and errorCode."""
    # BER encode: SEQUENCE { [0] INTEGER version, [4] INTEGER errorCode }
```

**Changes to `NLAHandler.__init__`:**

Add `disconnectCallback: Callable` parameter — called after hash capture to trigger clean connection teardown.

### CLI Changes

New arguments in `buildArgParser()`:

```python
parser.add_argument("--nla-fallback",
    help="When the server requires NLA, only capture the NTLM hash and "
         "disconnect cleanly. Do not attempt credential-replay CredSSP. "
         "Use this if you only need hashes, not full sessions.",
    action="store_true")
```

### Config Changes

New fields in `MITMConfig`:

```python
self.nlaFallback: bool = False
"""Skip credential-replay CredSSP, only capture hash and disconnect."""
```

---

## Testing Plan

### PROXY Protocol

| # | Type | Test |
|---|------|------|
| 1 | Unit | Parse valid v1 header (TCP4), verify src/dst IP and port |
| 2 | Unit | Parse valid v1 header (TCP6), verify IPv6 addresses |
| 3 | Unit | Parse valid v1 header (UNKNOWN), verify no address extracted |
| 4 | Unit | Parse valid v2 header (IPv4/TCP), verify all fields |
| 5 | Unit | Parse valid v2 header (IPv6/TCP), verify all fields |
| 6 | Unit | Parse v2 header with LOCAL command, verify command field |
| 7 | Unit | Parse v2 header with TLV extensions, verify address + TLVs logged |
| 8 | Unit | Reject truncated v1 header (no `\r\n`) |
| 9 | Unit | Reject truncated v2 header (< 16 bytes) |
| 10 | Unit | Reject v2 header with wrong signature |
| 11 | Unit | Reject v2 header with unsupported version (not 0x2) |
| 12 | Unit | Verify data after header is returned as remainder |
| 13 | Unit | Auto-detect v1 vs v2 correctly |
| 14 | Integration | TCP connection with v2 header → PyRDP logs correct client IP |

### CredSSP Client

| # | Type | Test |
|---|------|------|
| 15 | Unit | NTOWFv2: known password → expected response key (MS-NLMP test vectors) |
| 16 | Unit | NTLMv2 response computation with known challenge/timestamp → expected NTProofStr |
| 17 | Unit | Session key derivation → expected ExportedSessionKey |
| 18 | Unit | pubKeyAuth encryption (version 2-4 format) with known key and public key |
| 19 | Unit | pubKeyAuth encryption (version 5+ format) with nonce |
| 20 | Unit | TSRequest BER serialization → valid ASN.1 |
| 21 | Unit | TSRequest BER parsing → correct fields extracted |
| 22 | Unit | SPNEGO NegTokenInit wrapping of NTLMSSP NEGOTIATE |
| 23 | Unit | SPNEGO NegTokenResp wrapping of NTLMSSP AUTHENTICATE |
| 24 | Unit | TSCredentials serialization (TSPasswordCreds) |
| 25 | Unit | TSRequest error response serialization (version + errorCode only) |
| 26 | Integration | CredSSPClient authenticates to test NLA server with known creds |
| 27 | Integration | Full credential-replay flow: client (TLS-only) → PyRDP → server (NLA) |

### Hash Capture Fallback

| # | Type | Test |
|---|------|------|
| 28 | Unit | After AUTHENTICATE capture, error TSRequest sent and disconnect called |
| 29 | Integration | `--nla-fallback` mode: hash captured, clean disconnect, no SSL errors |
| 30 | Integration | Credential-replay failure → automatic fallback to hash capture |

### Regression

| # | Type | Test |
|---|------|------|
| 31 | Integration | Non-NLA connection works unchanged (TLS-only MITM) |
| 32 | Integration | Transparent proxy mode still works |
| 33 | Integration | Existing unit tests pass |
| 34 | Integration | PROXY protocol disabled by default — no behavioral change |

---

## File Change Summary

| File | Change | Description |
|------|--------|-------------|
| `pyrdp/core/proxy_protocol.py` | **NEW** | `ProxyProtocolHeader` dataclass, `parseProxyProtocolV1()`, `parseProxyProtocolV2()`, `parseProxyProtocol()` auto-detect |
| `pyrdp/security/credssp.py` | **NEW** | `CredSSPClient` class: full NTLM computation chain, SPNEGO wrapping, TSRequest serialization, pubKeyAuth (v2-4 and v5+), TSCredentials |
| `test/test_proxy_protocol.py` | **NEW** | Unit tests #1-14 |
| `test/test_credssp_client.py` | **NEW** | Unit tests #15-27 |
| `test/test_nla_improvements.py` | **NEW** | Unit tests #28-30 |
| `pyrdp/layer/tcp.py` | Modified | `proxyProtocolEnabled` flag, `AWAITING_PROXY_HEADER` / `NORMAL_OPERATION` state machine in `dataReceived()`, `proxyInfo` attribute |
| `pyrdp/mitm/RDPMITM.py` | Modified | `onCredentialsCaptured()`, `performServerCredSSP()`, `replayBufferedHandshake()`, modified `connectToServer()` |
| `pyrdp/mitm/SecurityMITM.py` | Modified | Credential extraction callback when Client Info PDU received |
| `pyrdp/mitm/X224MITM.py` | Modified | `serverRequiresNLA` handling, `nlaFallback` support, improved logging |
| `pyrdp/mitm/TCPMITM.py` | Modified | Use `proxyInfo` for client IP in `onClientConnection()` |
| `pyrdp/mitm/state.py` | Modified | `serverRequiresNLA`, `capturedCredentials`, `handshakeBuffer`, `pendingServerCredSSP` |
| `pyrdp/mitm/config.py` | Modified | `proxyProtocol: bool`, `nlaFallback: bool` |
| `pyrdp/mitm/cli.py` | Modified | `--proxy-protocol`, `--nla-fallback` arguments |
| `pyrdp/core/mitm.py` | Modified | Pass `proxyProtocol` config to TCP layer |
| `pyrdp/security/nla.py` | Modified | `disconnectCallback`, TSRequest error response after hash capture in ntlmCapture mode |
| `pyrdp/parser/rdp/ntlmssp.py` | Modified | `writeTSRequestError()`, `rewriteTSRequestVersion()` |

---

## Implementation Order

| Step | Feature | Depends On | Complexity | Description |
|------|---------|------------|------------|-------------|
| 1 | PROXY protocol | Nothing | Low | `proxy_protocol.py` parser + TCP layer buffering + CLI flag |
| 2 | Clean hash capture | Nothing | Low | TSRequest error response + clean disconnect in NLAHandler |
| 3 | CredSSP client core | Nothing | High | NTLM computation, SPNEGO wrapping, TSRequest serialization, pubKeyAuth |
| 4 | Credential-replay flow | Step 3 | Medium | Wire CredSSP client into RDPMITM, SecurityMITM callback, X224MITM changes |
| 5 | Session bridging | Step 4 | Medium | PDU buffering, replay to server, MCS response adaptation, session sync |
| 6 | Version downgrade | Step 3 | Low | Built into CredSSP client version negotiation |
| 7 | NLA logging + fallback flag | Step 2 | Low | CLI flag, structured JSON logging, fallback mode |

Steps 1 and 2 can be done in parallel. Step 3 is the critical path.
