# Protocol Intelligence Enhancements

All protocol-level intelligence enhancements added to the PyRDP fork and the Go rdp-proxy. Implemented and tested 2026-06-29.

---

## PyRDP (Python) Enhancements

### 1. NTLM Type 1 (NEGOTIATE) Parsing

**Files**: `pyrdp/parser/rdp/ntlmssp.py`, `pyrdp/pdu/rdp/ntlmssp.py`

**Before**: `NTLMSSPNegotiatePDU` was an empty shell -- no fields parsed from the NEGOTIATE message body.

**After**: Extracts `negotiateFlags`, `domainName`, `workstation`, and `version` (OS major/minor/build + NTLM revision) from the Type 1 message.

**Intelligence value**: Negotiate flags like `NEGOTIATE_EXTENDED_SESSION`, `NEGOTIATE_56`, and `NEGOTIATE_128` fingerprint the client implementation. mstsc, FreeRDP, and attack tools each set distinct flag combinations. The workstation name field in Type 1 is sometimes populated before the Type 3 AUTHENTICATE message, giving early attribution even if the attacker disconnects before completing authentication.

---

### 2. NTLM Flag Decode

**File**: `pyrdp/enum/ntlmssp.py`

**Function**: `decodeNTLMFlags(flags: int) -> dict`

Turns a raw NTLM negotiate flags bitmask into a readable boolean dictionary.

**Fields decoded**: `unicode`, `oem`, `request_target`, `sign`, `seal`, `datagram`, `lm_key`, `ntlm`, `always_sign`, `target_type_domain`, `target_type_server`, `extended_session`, `target_info`, `version`, `128bit`, `key_exch`, `56bit`.

**Intelligence value**: Different RDP clients and attack tools set different flag combinations. The decoded flags map directly to MS-NLMP section 2.2.2.5 and allow immediate classification of the connecting software without waiting for later protocol phases.

---

### 3. Rich NTLM Challenge (Hash Capture Mode)

**File**: `pyrdp/parser/rdp/ntlmssp.py`

**Function**: `writeNTLMSSPChallenge()` now accepts separate parameters for NetBIOS domain, computer name, DNS domain, DNS computer name, and DNS tree name. Builds proper AV_PAIRs including `MsvAvTimestamp`.

**Before**: Used the static string `WINNT` for ALL AV_PAIR values. No timestamp AV_PAIR was included.

**After**: Realistic AV_PAIRs matching what a real domain-joined Windows server sends. The timestamp uses Windows FILETIME format (100-nanosecond intervals since 1601-01-01).

**CLI flags**: `--ntlm-hostname`, `--ntlm-domain`, `--ntlm-dns-domain`

**Intelligence value**: Better deception -- the challenge message looks like a real domain-joined server rather than a bare-bones stub. The `MsvAvTimestamp` AV_PAIR is required by some modern NTLMv2 clients; without it, certain clients refuse to complete the NTLM exchange, meaning pre-enhancement the honeypot was invisible to a subset of scanners. With realistic AV_PAIRs, more attackers complete authentication, yielding more captured NTLMv2 hashes.

---

### 4. SPNEGO mechType Detection

**File**: `pyrdp/security/nla.py`

Parses the SPNEGO `NegTokenInit` to detect which authentication mechanisms the client offers.

**Detected OIDs**:

| OID | Mechanism |
|-----|-----------|
| `1.3.6.1.4.1.311.2.2.10` | NTLMSSP |
| `1.2.840.113554.1.2.2` | KRB5 (Kerberos 5) |
| `1.2.840.48018.1.2.2` | MS_KRB5 (Microsoft Kerberos) |
| `1.3.6.1.4.1.311.2.2.30` | NEGOEX |

**State field**: `state.spnegoMechTypes` (list of strings)

**Intelligence value**: The combination of offered mechanisms immediately classifies the client. `[NTLMSSP]` only means an attack tool or stripped-down client. `[NTLMSSP, KRB5, MS_KRB5]` means a domain-joined Windows machine. The presence of `NEGOEX` indicates modern Windows with extended negotiation support (Windows 8+). This classification happens before any credentials are exchanged.

---

### 5. X.224 Correlation ID Logging

**File**: `pyrdp/mitm/X224MITM.py`

Logs the 16-byte Correlation ID GUID from the X.224 Connection Request PDU.

**State field**: `state.correlationId` (hex string)

**Intelligence value**: The Correlation ID is unique per client installation and persists across sessions. It tracks the same machine across IP address changes (VPN hops, NAT changes, new proxy). Present since Windows 8+. Absence of a Correlation ID is itself a signal -- older clients and many attack tools omit it.

---

### 6. X.224 Requested Protocols Logging

**File**: `pyrdp/mitm/X224MITM.py`

Logs and decodes the `requestedProtocols` bitmask from the X.224 Connection Request.

**State field**: `state.clientRequestedProtocols` (int)

**Protocol values**:

| Value | Meaning |
|-------|---------|
| `0x00` | Standard RDP Security |
| `0x01` | SSL (TLS) only |
| `0x02` | HYBRID (CredSSP/NLA) |
| `0x08` | HYBRID_EX (CredSSP with Early User Auth) |

**Intelligence value**: This is one of the earliest classification signals in the protocol. Scanners typically request `0x00` (Standard RDP) or `0x01` (SSL only). Real mstsc clients request `0x0b` (SSL + HYBRID + HYBRID_EX). The value immediately classifies the connection type before any cryptographic exchange occurs.

---

### 7. Connection Phase Timestamps

**Files**: `pyrdp/mitm/RDPMITM.py`, `pyrdp/mitm/state.py`

Records monotonic timestamps at each connection phase: `init`, `tls_start`.

**State field**: `state.connectionTimestamps` (dict mapping phase name to monotonic time)

**Intelligence value**: The time delta between TCP connect and TLS start reveals scanning speed. Automated tools complete the pre-TLS handshake in under 100ms. Human-driven connections take longer due to network latency and the time the RDP client spends rendering its UI before initiating the TLS upgrade. This metric cleanly separates bulk scanners from interactive sessions.

---

### 8. IME Filename + Channel Fingerprinting

**File**: `pyrdp/mitm/MCSMITM.py`

Logs the IME (Input Method Editor) filename from the MCS Connect Initial PDU and creates a channel combination signature from the requested virtual channels.

**State fields**:
- `rdpFingerprint["ime_filename"]` -- the IME DLL name from the client
- `rdpFingerprint["channel_signature"]` -- sorted, joined channel name string
- `rdpFingerprint["channel_anomaly"]` -- boolean flag for suspicious channel combinations

**Intelligence value**: The IME filename reveals CJK (Chinese, Japanese, Korean) input method configuration, indicating non-Western attacker origin. The channel signature uniquely identifies client software: missing `cliprdr` (clipboard redirection) means a headless script that has no use for clipboard sharing. Missing `rdpsnd` (audio) is normal for servers but unusual for workstation clients. The combination of requested channels is a stable fingerprint across sessions from the same tool.

---

### 9. alternateShell Alerting

**File**: `pyrdp/mitm/SecurityMITM.py`

Warns when the Client Info PDU contains a non-empty `alternateShell` field.

**State field**: `clientInfo["shell_suspicious"]` (boolean)

**Intelligence value**: In legitimate RDP usage, `alternateShell` is almost never set -- users connect to the default desktop. A non-empty value almost always indicates an attacker specifying a command to execute on login: `cmd.exe`, `powershell.exe`, a custom payload path, or a RemoteApp abuse. This is a high-confidence indicator of malicious intent.

---

### 10. Performance Flags Decode

**File**: `pyrdp/mitm/SecurityMITM.py`

Decodes the Client Info PDU performance flags bitmask into readable booleans and flags fully-disabled connections as scripted.

**State fields**:
- `clientInfo["performance_flags_decoded"]` -- dict of individual flag booleans
- `clientInfo["scripted_connection"]` -- boolean, true when all visual effects are disabled

**Decoded flags**: `disable_wallpaper`, `disable_fullwindowdrag`, `disable_menuanimations`, `disable_theming`, `disable_cursor_shadow`, `disable_cursor_settings`, `disable_font_smoothing`, `disable_desktop_composition`.

**Intelligence value**: When all visual effects are disabled, the connection is almost certainly automated -- no human user disables every single visual feature. Real users typically keep at least font smoothing or theming enabled. A `scripted_connection: true` flag is a strong signal of attack tooling or automated lateral movement.

---

### 11. Timezone Bias Extraction

**File**: `pyrdp/mitm/SecurityMITM.py`

Extracts numeric UTC offset bias values from the Client Info PDU timezone structure.

**State fields**:
- `clientInfo["timezone_bias_minutes"]` -- base UTC offset in minutes
- `clientInfo["timezone_standard_bias"]` -- additional standard time offset
- `clientInfo["timezone_daylight_bias"]` -- additional daylight saving offset

**Intelligence value**: The numeric bias is more precise and harder to spoof than the timezone name string. Combined with keyboard layout (from MCS Connect Initial), it gives a strong geographic signal. A mismatch between timezone bias and keyboard layout (e.g., UTC+8 bias with a US English keyboard) suggests the attacker is using a VPN/proxy from a different region than their actual location.

---

### 12. CredSSP Version Bump

**File**: `pyrdp/enum/ntlmssp.py`

Updated the NTLM challenge version fields:
- CredSSP version: 5 -> 6
- OS version: Server 2012 -> Windows 10 2004

**Intelligence value**: Presents as a modern server rather than an outdated one. CredSSP v6 supports SHA-256 public key authentication binding, which is compliant with CVE-2018-0886 mitigations. Older CredSSP versions may cause modern clients to refuse the connection or downgrade their security, reducing the honeypot's capture rate.

---

### 13. Server 2025 SKIP_CHANNELJOIN Fix

**File**: `pyrdp/mitm/MCSMITM.py`

Strips the `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED` flag (0x08) from the MCS Connect Response `earlyCapabilityFlags`. When a client sends Channel Join Requests (because it no longer sees the flag), PyRDP responds with synthetic Channel Join Confirm PDUs.

**Why this exists**: Windows Server 2025 introduced the `SKIP_CHANNELJOIN` optimization flag. When set, clients skip sending Channel Join Request PDUs entirely. PyRDP's MITM architecture depends on those join requests to build its internal channel routing infrastructure. Without this fix, PyRDP would appear to connect successfully but silently drop all client data after the MCS phase -- no keystrokes, no clipboard, no drive redirection, no graphical output would be captured.

**Behavior**: The flag is stripped from the server's response before forwarding to the client. The client then sends Channel Join Requests as it would for any pre-2025 server. PyRDP generates synthetic Join Confirms to complete the handshake on the client side while the real server (which expected no joins) continues normally.

---

## Go rdp-proxy Enhancements

### 14. TLS ClientHello Fingerprinting

**File**: `internal/scanner/respond.go`

Uses the `GetConfigForClient` TLS callback to capture the full ClientHello message contents: cipher suites, supported TLS versions, elliptic curves, signature schemes, SNI (Server Name Indication), and ALPN (Application-Layer Protocol Negotiation) values.

**Intelligence value**: The TLS ClientHello definitively identifies client software. mstsc, FreeRDP, rdesktop, Python SSL libraries, and Metasploit each produce distinct ClientHello fingerprints. The raw cipher suite and extension arrays are more granular than JA3/JA4 hashes for analysis, though hashes can be derived from the captured data. This fingerprint is available before any RDP-level exchange occurs.

---

### 15. Scanner NTLM Type 3 Parsing

**File**: `internal/scanner/respond.go`

Parses the NTLM AUTHENTICATE (Type 3) message from scanner responses to extract username, domain, workstation, and the NTLMv2 response hash.

**Before**: Scanner responses received after the NTLM CHALLENGE were read from the connection and discarded without inspection.

**After**: Full extraction of credentials from any scanner that completes the NTLM authentication exchange.

**Intelligence value**: Captures NTLMv2 hashes from scanners that go beyond certificate-grab-only behavior. These hashes can be cracked offline or correlated across honeypot nodes to track the same scanning infrastructure. Most scanners disconnect after receiving the server certificate or the NTLM challenge; those that send a Type 3 are running more sophisticated tooling worth tracking.

---

### 16. X.224 RequestedProtocols Logging

**File**: `internal/proxy/proxy.go`

Logs the `requestedProtocols` bitmask from every X.224 Connection Request received by the proxy.

**Intelligence value**: Classifies connections at the earliest possible protocol stage, before any authentication or TLS negotiation. Values of `0x00` or `0x01` indicate a scanner or legacy client. Values of `0x03` or `0x0b` indicate a real RDP client capable of CredSSP/NLA. This classification determines routing decisions (scanner responder vs. PyRDP forwarding) and enriches the connection log.

---

### 17. Connection Timing

**File**: `internal/proxy/proxy.go`

Logs the elapsed milliseconds between TCP accept and the arrival of the X.224 Connection Request.

**Intelligence value**: Scanners send the X.224 Connection Request immediately upon TCP connection (0-5ms delay). Real clients introduce delays due to DNS resolution, TLS library initialization, and UI rendering before the RDP stack sends its first protocol message. A timing threshold cleanly separates bulk scanning from interactive connections.

---

### 18. HYBRID-Aware Scanner Detection

**File**: `internal/proxy/proxy.go`

Scanner detection now evaluates both the routing cookie content AND the `requestedProtocols` bitmask to make classification decisions.

**Before**: An empty routing cookie was sufficient to classify a connection as a scanner. This misclassified mstsc's legitimate pre-authentication certificate probe, which sends an empty cookie but requests HYBRID (CredSSP) negotiation.

**After**: The classification logic is:
- Empty cookie + no HYBRID requested = scanner (routed to scanner responder)
- Empty cookie + HYBRID requested = real client pre-auth probe (forwarded to PyRDP)
- Valid cookie = real client (forwarded to PyRDP)

This eliminates false-positive scanner classification of legitimate mstsc connections that perform a certificate validation probe before the user enters credentials.

---

## State Fields Summary

All intelligence fields are stored in `RDPMITMState` and emitted in fleet-level events for correlation and analysis.

| Field | Type | Source |
|---|---|---|
| `rdpFingerprint` | dict | MCS Connect Initial -- clientBuild, keyboardLayout, clientName, resolution, channels, IME filename, channel signature, channel anomaly |
| `clientInfo` | dict | Client Info PDU -- username, domain, timezone bias, performance flags (decoded), scripted_connection flag, alternateShell, shell_suspicious flag |
| `ntlmInfo` | dict | NTLM AUTHENTICATE (Type 3) -- user, domain, workstation, NTLMv2 hash, decoded negotiate flags |
| `ntlmNegotiateInfo` | dict | NTLM NEGOTIATE (Type 1) -- negotiate flags (decoded), workstation, domain, client OS version |
| `spnegoMechTypes` | list | SPNEGO NegTokenInit -- offered authentication mechanisms (NTLMSSP, KRB5, MS_KRB5, NEGOEX) |
| `correlationId` | str | X.224 Connection Request -- 16-byte GUID, hex-encoded |
| `clientRequestedProtocols` | int | X.224 Connection Request -- protocol negotiation bitmask |
| `connectionTimestamps` | dict | Various connection phases -- monotonic timestamps keyed by phase name |
| `serverCertInfo` | dict | Server TLS certificate -- CN, issuer, SHA-256 fingerprint, validity dates |

---

## Fingerprinting Cheat Sheet

Quick reference for classifying connections using the captured fields.

### By requestedProtocols

| Value | Likely Client |
|---|---|
| `0x00` | Scanner (zgrab2, masscan RDP module, custom script) |
| `0x01` | Scanner or legacy client (SSL only, no NLA) |
| `0x03` | FreeRDP, xfreerdp, or older mstsc (SSL + HYBRID) |
| `0x0b` | Modern mstsc, Windows 10/11 (SSL + HYBRID + HYBRID_EX) |

### By SPNEGO mechTypes

| Offered Mechanisms | Likely Client |
|---|---|
| `[NTLMSSP]` | Attack tool, standalone scanner, non-domain client |
| `[NTLMSSP, KRB5, MS_KRB5]` | Domain-joined Windows workstation |
| `[NTLMSSP, KRB5, MS_KRB5, NEGOEX]` | Modern domain-joined Windows (8+) |

### By Performance Flags

| Pattern | Likely Client |
|---|---|
| All effects disabled | Automated tool / script (`scripted_connection: true`) |
| Wallpaper + composition disabled, rest enabled | Human on slow link |
| Nothing disabled | Human on fast LAN |

### By Connection Timing

| TCP-to-X.224 Delay | Likely Client |
|---|---|
| 0-10ms | Bulk scanner |
| 10-100ms | Automated tool with some initialization overhead |
| 100ms+ | Human-driven client or tool with DNS/TLS overhead |
