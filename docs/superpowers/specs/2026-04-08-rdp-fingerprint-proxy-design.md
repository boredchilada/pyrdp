# RDP Fingerprint Proxy — Design Spec

**Date:** 2026-04-08
**Status:** Draft

---

## Problem Statement

PyRDP running on Linux is trivially fingerprintable as "not a real Windows RDP server" by scanners (Shodan, Censys, nmap), threat actors, and automated bot networks. This undermines its use as a honeypot — sophisticated attackers will avoid it.

The Zirngibl et al. (WTMC 2022) paper demonstrated detection of 1,123 RDPY and 84 Heralding honeypot instances in the wild using protocol-level fingerprinting. PyRDP is vulnerable to the same techniques.

---

## Detection Vectors (Ranked by Reliability)

### 1. TLS Record Packing (Binary, Deterministic)

**The single most reliable signal.** Windows SChannel packs multiple TLS handshake messages (ServerHello, Certificate, ServerHelloDone) into a **single TLS record**. OpenSSL (used by Twisted/PyRDP) sends **each in a separate TLS record**.

```
SChannel (Windows):
  Record 1: [ServerHello + Certificate + ServerHelloDone]

OpenSSL (PyRDP):
  Record 1: [ServerHello]
  Record 2: [Certificate]
  Record 3: [ServerHelloDone]
```

Any tool that counts TLS record boundaries during the handshake can distinguish these instantly. Used by TLS Prober and the WTMC 2022 paper.

### 2. TCP/IP Stack Fingerprint (Passive, Deterministic)

| Parameter | Windows | Linux (PyRDP) |
|-----------|---------|---------------|
| Initial TTL | 128 | 64 |
| TCP Window Size (SYN-ACK) | 65535 | 29200 or 64240 |
| Window Scale | 8 | 7 |
| TCP Timestamps | **Absent** | **Present** |
| TCP Options Order | MSS, NOP, WS, NOP, NOP, SACK | MSS, SACK, Timestamp, NOP, WS |
| DF bit | Set | Set |

**TCP timestamps are the biggest giveaway.** Windows does not send them by default. Linux always does. Detectable passively by any packet capture (p0f, nmap, Shodan).

nmap OS fingerprint signatures:
```
Windows: 4:128:0:*:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
Linux:   4:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0
```

### 3. TLS Cipher Suite Ordering

Windows SChannel (Server 2019+ / Win10 v1809) default cipher preference:

```
Priority  Hex     Suite
────────  ──────  ──────────────────────────────────────────────
1         0xC02C  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
2         0xC02B  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
3         0xC030  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
4         0xC02F  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
5         0x009F  TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
6         0x009E  TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
7         0xC024  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
8         0xC023  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
9         0xC028  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
10        0xC027  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
11        0xC00A  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
12        0xC009  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
13        0xC014  TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
14        0xC013  TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
15        0x009D  TLS_RSA_WITH_AES_256_GCM_SHA384
16        0x009C  TLS_RSA_WITH_AES_128_GCM_SHA256
17        0x003D  TLS_RSA_WITH_AES_256_CBC_SHA256
18        0x003C  TLS_RSA_WITH_AES_128_CBC_SHA256
19        0x0035  TLS_RSA_WITH_AES_256_CBC_SHA
20        0x002F  TLS_RSA_WITH_AES_128_CBC_SHA
21        0x000A  TLS_RSA_WITH_3DES_EDE_CBC_SHA
```

Key tells:
- ECDHE_ECDSA before ECDHE_RSA (SChannel pattern)
- GCM before CBC within each group
- **No ChaCha20-Poly1305** (0xCCA8, 0xCCA9) — SChannel doesn't support it. OpenSSL default includes it.
- **No TLS 1.3** for RDP, even on Server 2022
- `extended_master_secret` extension present (enforced since CVE-2019-1318)
- `renegotiation_info` extension present

### 4. Certificate Characteristics

Windows auto-generated RDP self-signed certificate:

| Property | Windows Default | Common Honeypot Tell |
|----------|----------------|---------------------|
| Subject CN | `CN=DESKTOP-ABC1234` (NetBIOS hostname) | Lowercase, dots, non-Windows naming |
| Key Algorithm | RSA 2048-bit | EC keys, 4096-bit RSA, 1024-bit |
| Signature | SHA256withRSA (Win 8.1+) | SHA1, or unusual algorithms |
| Validity | ~6 months, auto-renewed | 1 year, 10 years, or expired |
| EKU | `1.3.6.1.4.1.311.54.1.2` (Remote Desktop Auth) | Missing this OID entirely |
| Key Usage | Key Encipherment, Data Encipherment | Digital Signature only |
| Serial | 16 bytes, random (CryptoAPI) | Small sequential integers (OpenSSL default) |
| Extensions | Minimal, no Basic Constraints | OpenSSL-style Authority/Subject Key ID |

### 5. NTLM TargetInfo AV_PAIRs

When NLA/CredSSP is probed (even with null credentials), the server's NTLMSSP CHALLENGE contains:

| AV_PAIR | What it reveals | Honeypot tell |
|---------|----------------|---------------|
| MsvAvNbComputerName | NetBIOS hostname | Missing or inconsistent |
| MsvAvNbDomainName | NetBIOS domain | Missing |
| MsvAvDnsComputerName | FQDN | Missing or doesn't match |
| MsvAvDnsDomainName | DNS domain | Missing |
| MsvAvTimestamp | FILETIME (100ns since 1601-01-01) | Unix epoch, wrong format, static |
| Product_Version | OS version (e.g., 10.0.19041) | Missing or inconsistent with other signals |

nmap's `rdp-ntlm-info` script specifically extracts these.

### 6. RDP Server Core Data Version

In the MCS Connect Response (TS_UD_SC_CORE), the `version` field maps directly to Windows versions:

| Hex | RDP Version | Windows Version |
|-----|-------------|----------------|
| 0x0008000A | 10.5 | Windows 10 v1809 / Server 2019 |
| 0x0008000D | 10.8 | Windows 10 v2004 |
| 0x00080010 | 10.11 | Windows 11 / Server 2022 |
| 0x00080011 | 10.12 | Windows 11 22H2+ |

`earlyCapabilityFlags` must also be consistent with the version.

### 7. Cross-Layer Timing Asymmetry

NDSS 2025 (dMAP) paper: when a proxy terminates TCP locally but relays TLS to a backend, TCP RTT is fast (local) while TLS RTT is slow (backend). Measurable with ~20 probes, ~95% accuracy.

```
Detectable:   TCP SYN-ACK: 2ms    TLS ServerHello: 150ms   ← proxy detected
Real Windows: TCP SYN-ACK: 150ms  TLS ServerHello: 155ms   ← consistent RTT
```

---

## Solution: Standalone RDP Fingerprint Proxy

### Architecture

```
Internet ──► RDP Fingerprint Proxy (port 3389)
              │
              ├─ L3/L4: TCP/IP stack masquerading (Windows fingerprint)
              ├─ L5:    TLS termination with SChannel-like behavior
              ├─ L6:    Certificate generation matching Windows patterns
              ├─ L7:    NTLM challenge response with proper AV_PAIRs
              │
              └──► PyRDP (via PROXY protocol v2, gets real client IP)
                    │
                    └──► Target RDP Server
```

### Why Standalone (Not Built Into PyRDP)

- PyRDP uses Twisted/OpenSSL — **cannot** fix TLS record packing without replacing the TLS stack
- TCP fingerprint requires OS-level changes (iptables, raw sockets) — wrong to embed in an RDP tool
- Separation of concerns: fingerprint masking is infrastructure, not RDP logic
- Reusable for other honeypots (not just PyRDP)
- Independently testable — nmap the proxy directly to verify

### Language Choice: Go

- Native TLS library (`crypto/tls`) allows full control over TLS record packing, cipher suites, extensions
- Direct control over TCP socket options (TTL, window size, timestamps)
- Single static binary — easy to deploy
- Cross-platform compilation
- Good performance for connection proxying

Python alternative considered but rejected: Python's `ssl` module wraps OpenSSL — cannot control record packing. Would need ctypes or a C extension to match SChannel behavior.

---

## Components

### Component 1: TCP Stack Masquerading

**Goal:** Make the proxy's TCP fingerprint match Windows 10/Server 2019.

**Implementation:**

On the **listening socket**, set socket options:

```go
// Set TTL to 128 (Windows default)
syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 128)

// Disable TCP timestamps (Windows default: off)
// Linux: /proc/sys/net/ipv4/tcp_timestamps = 0
// Or per-socket via TCP_NODELAY + custom SYN-ACK

// Set initial window size to 65535
syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_WINDOW_CLAMP, 65535)
```

**Per-host iptables rules** (required for some parameters that can't be set per-socket):

```bash
# Set TTL on outgoing packets from proxy port
iptables -t mangle -A OUTPUT -p tcp --sport 3389 -j TTL --ttl-set 128

# Disable TCP timestamps for proxy port
iptables -t mangle -A OUTPUT -p tcp --sport 3389 -j TCPOPTSTRIP --strip-options timestamp

# Alternative: global sysctl (affects whole host)
sysctl -w net.ipv4.tcp_timestamps=0
```

**TCP options ordering** is harder — Linux kernel determines the order. The proxy documents which parameters can be changed and which require kernel-level patching or the `nftables` approach.

**Realistic scope:** TTL=128 and disabling timestamps covers the two biggest signals. Full TCP options reordering requires custom kernel modules and is out of scope for v1.

### Component 2: TLS Termination (SChannel Mimicry)

**Goal:** TLS handshake that looks identical to Windows SChannel.

**Implementation using Go's `crypto/tls`:**

```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{windowsCert},
    MinVersion:   tls.VersionTLS12,
    MaxVersion:   tls.VersionTLS12,  // No TLS 1.3 (SChannel doesn't use it for RDP)

    // SChannel cipher suite order
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        tls.TLS_RSA_WITH_AES_128_CBC_SHA,
    },

    CurvePreferences: []tls.CurveID{
        tls.X25519,
        tls.CurveP384,
        tls.CurveP256,
    },
}
```

**TLS record packing:** Go's `crypto/tls` by default sends handshake messages in separate records (like OpenSSL). To mimic SChannel, we need to buffer handshake messages and write them in a single TLS record:

```go
// Custom handshake writer that packs ServerHello + Certificate + ServerHelloDone
// into a single TLS record.
//
// Approach: intercept the TLS handshake at the record layer.
// Go's crypto/tls doesn't expose this directly, so we either:
// 1. Patch crypto/tls (fork the package, modify writeRecord)
// 2. Use a raw TLS implementation (e.g., github.com/pion/dtls adapted, or custom)
// 3. Buffer at the TCP write level — coalesce multiple small writes into one
//
// Option 3 (TCP write coalescing) is simplest:
// - Set TCP_NODELAY = false (enable Nagle's algorithm) during handshake
// - All handshake records get coalesced into a single TCP segment
// - Set TCP_NODELAY = true after handshake for low-latency data forwarding
//
// This doesn't change the TLS record boundaries (still multiple records)
// but makes them appear in a single TCP segment, which fools simpler detectors.
//
// For full record packing (multiple handshake messages in one TLS record),
// a custom TLS implementation or forked crypto/tls is needed.
```

**Pragmatic v1 approach:** TCP write coalescing (Nagle during handshake) + correct cipher suites + correct TLS version + correct extensions. This defeats JA3S fingerprinting and simple packet-level detectors. Full TLS record packing (defeating TLS Prober-level analysis) requires a forked crypto/tls and is a v2 enhancement.

### Component 3: Certificate Generation

**Goal:** Generate certificates that match Windows auto-generated RDP certificates.

**Implementation:**

```go
type WindowsCertConfig struct {
    Hostname     string        // NetBIOS-style: "DESKTOP-ABC1234"
    ValidityDays int           // ~180 days (6 months)
    KeySize      int           // 2048
    SignatureAlg x509.SignatureAlgorithm // SHA256WithRSA
}

func GenerateWindowsRDPCert(cfg WindowsCertConfig) (*tls.Certificate, error) {
    template := &x509.Certificate{
        SerialNumber: randomBigInt(16),  // 16-byte random (CryptoAPI style)
        Subject: pkix.Name{
            CommonName: cfg.Hostname,
        },
        NotBefore: time.Now().Add(-24 * time.Hour),  // started yesterday
        NotAfter:  time.Now().Add(time.Duration(cfg.ValidityDays) * 24 * time.Hour),

        KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,

        // Microsoft Remote Desktop Authentication EKU
        ExtKeyUsage: []x509.ExtKeyUsage{},
        UnknownExtKeyUsage: []asn1.ObjectIdentifier{
            {1, 3, 6, 1, 4, 1, 311, 54, 1, 2},  // MS RDP Auth OID
        },

        DNSNames: []string{cfg.Hostname},

        // NO BasicConstraints (Windows auto-gen doesn't include it)
        // NO AuthorityKeyIdentifier (Windows auto-gen doesn't include it)
        // NO SubjectKeyIdentifier (Windows auto-gen doesn't include it)
        BasicConstraintsValid: false,
    }
    // ... generate RSA 2048 key, self-sign with SHA256
}
```

**Hostname generation:** Generate realistic Windows NetBIOS hostnames:
- Format: `DESKTOP-XXXXXXX` (7 random alphanumeric chars, uppercase)
- Or: `WIN-XXXXXXXXXXX` (11 random)
- Or: `EC2AMAZ-XXXXXXX` (for AWS-themed deployments)
- Configurable via `--hostname` flag

**Certificate rotation:** Auto-regenerate every ~180 days to match Windows behavior. Persist cert+key to disk so it's stable between restarts.

### Component 4: NTLM Challenge Response (Pre-Auth Probe Handling)

**Goal:** When scanners send NTLM NEGOTIATE probes (like nmap's `rdp-ntlm-info`), respond with a convincing Windows NTLM CHALLENGE containing proper AV_PAIRs.

**This happens BEFORE PyRDP is involved** — the probe is at the X224/CredSSP level and the proxy can respond directly without forwarding to PyRDP.

**Implementation:**

When the proxy receives a CredSSP TSRequest with an NTLMSSP NEGOTIATE_MESSAGE on a connection that hasn't completed X224 negotiation properly (scanner behavior), respond with a CHALLENGE containing:

```go
type NTLMConfig struct {
    NetBIOSHostname  string   // "DESKTOP-ABC1234" (same as cert CN)
    NetBIOSDomain    string   // "DESKTOP-ABC1234" (workgroup = hostname for standalone)
    DNSHostname      string   // "DESKTOP-ABC1234.local" or custom
    DNSDomain        string   // "" (empty for workgroup) or custom
    OSVersion        [3]byte  // {10, 0, 0} for Windows 10
    OSBuild          uint16   // 19041 for Windows 10 2004
}

func BuildNTLMChallenge(cfg NTLMConfig) []byte {
    avPairs := []AVPair{
        {MsvAvNbDomainName,    utf16le(cfg.NetBIOSDomain)},
        {MsvAvNbComputerName,  utf16le(cfg.NetBIOSHostname)},
        {MsvAvDnsDomainName,   utf16le(cfg.DNSDomain)},
        {MsvAvDnsComputerName, utf16le(cfg.DNSHostname)},
        {MsvAvTimestamp,       windowsFileTime(time.Now())},  // FILETIME format
        {MsvAvEOL,             []byte{}},
    }
    // ... build CHALLENGE_MESSAGE with Product_Version matching OSVersion+OSBuild
}
```

**FILETIME format:** 100-nanosecond intervals since January 1, 1601 UTC:
```go
func windowsFileTime(t time.Time) []byte {
    // Offset between Unix epoch and Windows epoch
    const epochDiff = 116444736000000000 // 100ns intervals
    ft := t.UnixNano()/100 + epochDiff
    buf := make([]byte, 8)
    binary.LittleEndian.PutUint64(buf, uint64(ft))
    return buf
}
```

**Connection routing decision:**
- If the connection is a scanner probe (incomplete X224, just NTLM probing): handle locally, don't forward to PyRDP
- If the connection is a real RDP client (proper X224 negotiation): forward to PyRDP via PROXY protocol

### Component 5: Connection Proxying

**Goal:** After TLS termination and fingerprint masking, forward the decrypted RDP stream to PyRDP.

**Flow:**

```
Client ──TLS──► Proxy ──PROXY protocol + plaintext──► PyRDP
                  │                                      │
                  │  (Proxy terminates client TLS,       │
                  │   PyRDP establishes its own TLS      │
                  │   with the client via startTLS)      │
                  │                                      │
                  └── Wait, this doesn't work...         │
```

**Problem:** PyRDP needs to do its own TLS with the client (for certificate cloning and key extraction). If the proxy terminates TLS, PyRDP can't do `startTLS` on an already-decrypted stream.

**Revised approach — TCP-level proxy with fingerprint injection:**

```
Client ──TCP──► Proxy ──PROXY protocol v2 + raw TCP──► PyRDP
                  │
                  ├─ TCP: Set TTL=128, strip timestamps on SYN-ACK
                  ├─ Does NOT terminate TLS
                  ├─ Pure TCP stream proxy after initial fingerprint setup
                  │
                  └─ Special handling for pre-auth probes:
                     If first bytes look like a scanner (NTLM probe without
                     proper X224), handle locally with fake NTLM challenge.
                     Otherwise, forward everything to PyRDP.
```

**This is much simpler and avoids the TLS termination problem.** The proxy:
1. Accepts TCP connection with Windows-like TCP parameters (TTL, no timestamps)
2. Sends PROXY protocol v2 header to PyRDP with real client IP
3. Forwards all subsequent bytes bidirectionally (pure TCP relay)
4. PyRDP handles TLS, X224, RDP — everything works as before

**The catch:** TLS cipher suites and record packing are handled by PyRDP (OpenSSL), not the proxy. The proxy can't fix those without terminating TLS.

**Hybrid approach for v1:**

The proxy operates at TCP level (fixing TCP fingerprint) and optionally handles scanner probes. TLS-level fixes require changes inside PyRDP itself (a separate enhancement):

| Vector | Fixed by Proxy | Fixed by PyRDP Changes | Status |
|--------|---------------|----------------------|--------|
| TCP TTL | Yes | N/A | v1 |
| TCP timestamps | Yes | N/A | v1 |
| TCP window size | Yes | N/A | v1 |
| Certificate format | No | Yes (cert generation) | v1 (PyRDP side) |
| TLS cipher suites | No | Partially (OpenSSL config) | v1 (PyRDP side) |
| TLS record packing | No | No (OpenSSL limitation) | v2 (needs custom TLS or Go TLS terminator) |
| NTLM AV_PAIRs | Yes (probe handling) | Yes (NLA handler) | v1 (both) |
| RDP version fields | No | Yes (MCS response) | v1 (PyRDP side) |

### Component 6: Scanner Probe Detection and Handling

**Goal:** Identify and respond to common RDP scanning tools locally, without forwarding to PyRDP. This prevents PyRDP from having to handle scanner probes (which often cause the SSL errors seen in the logs).

**Known scanner behaviors:**

| Scanner | Behavior | Detection |
|---------|----------|-----------|
| nmap `rdp-ntlm-info` | Sends X224 ConnReq, then NTLM NEGOTIATE with null creds | X224 cookie usually `mstshash=nmap` or empty |
| nmap `rdp-enum-encryption` | Tries multiple security protocols | Rapid reconnections cycling protocols |
| Shodan | Standard X224 probe, extracts cert + NTLM info | User-agent patterns, source IP ranges |
| masscan | SYN scan only (no RDP probing) | Handled by TCP accept |
| rdp-sec-check | Cycles all security/encryption combos | Similar to nmap rdp-enum |
| Generic bots | `mstshash=hello`, `mstshash=Administr` | Known cookie patterns |

**Probe handling:**

```
Connection received
    │
    ├── Read first bytes (X224 Connection Request)
    │
    ├── Is cookie a known scanner pattern? (mstshash=nmap, mstshash=hello, empty)
    │   ├── YES → Handle locally:
    │   │         Send X224 ConnConfirm, TLS handshake (Windows cert),
    │   │         if NTLM probe follows → send fake NTLM challenge with proper AV_PAIRs
    │   │         Log probe details, close connection
    │   │
    │   └── NO → Forward to PyRDP:
    │             Send PROXY protocol header + forward all bytes
    │
    └── Timeout (no X224 within 5s) → Close connection
```

**Configurable:** Scanner patterns configurable via config file. Option to forward ALL connections (including probes) to PyRDP with `--forward-all`.

---

## CLI Interface

```
rdp-proxy [flags]

Flags:
  --listen, -l          Listen address:port (default: 0.0.0.0:3389)
  --backend, -b         PyRDP backend address:port (default: 127.0.0.1:13389)
  --hostname            Windows hostname to impersonate (default: auto-generate DESKTOP-XXXXXXX)
  --os-version          Windows version string for NTLM (default: "10.0.19041" = Win10 2004)
  --os-build            Windows build number (default: 19041)
  --domain              NetBIOS domain name (default: same as hostname)
  --cert                Path to TLS certificate (default: auto-generate Windows-style)
  --key                 Path to TLS private key
  --cert-dir            Directory to store auto-generated certs (default: ./certs)
  --proxy-protocol      Send PROXY protocol v2 header to backend (default: true)
  --forward-all         Forward all connections to backend, including scanner probes
  --scanner-patterns    Path to scanner pattern config file
  --log-file            Log file path (default: stdout)
  --log-format          Log format: text or json (default: json)
  --ttl                 IP TTL value (default: 128)
  --no-timestamps       Disable TCP timestamps (default: true = disabled)
```

**Example deployment:**

```bash
# Start PyRDP listening on 13389 with PROXY protocol
pyrdp-mitm 10.0.0.100:3389 -l 13389 --proxy-protocol

# Start fingerprint proxy on public port 3389
rdp-proxy --listen 0.0.0.0:3389 --backend 127.0.0.1:13389 \
          --hostname DESKTOP-K7R2H4J --os-version "10.0.19041"
```

**Docker deployment:**

```yaml
services:
  rdp-proxy:
    image: rdp-proxy:latest
    ports:
      - "3389:3389"
    environment:
      - BACKEND=pyrdp:13389
      - HOSTNAME=DESKTOP-K7R2H4J
    cap_add:
      - NET_ADMIN  # for iptables TTL/timestamp manipulation

  pyrdp:
    image: pyrdp:latest
    command: pyrdp-mitm 10.0.0.100:3389 -l 13389 --proxy-protocol
    expose:
      - "13389"
```

---

## Configuration File

```yaml
# rdp-proxy.yaml
listen: "0.0.0.0:3389"
backend: "127.0.0.1:13389"
proxy_protocol: true

identity:
  hostname: "DESKTOP-K7R2H4J"
  domain: "WORKGROUP"
  dns_hostname: "DESKTOP-K7R2H4J"
  dns_domain: ""
  os_version: [10, 0, 19041]   # major, minor, build

certificate:
  auto_generate: true
  cert_dir: "./certs"
  validity_days: 180
  # Or provide your own:
  # cert_file: "/path/to/cert.pem"
  # key_file: "/path/to/key.pem"

tcp_masquerade:
  ttl: 128
  disable_timestamps: true
  window_size: 65535
  window_scale: 8

scanner_handling:
  forward_all: false
  known_patterns:
    - "mstshash=nmap"
    - "mstshash=hello"
    - "mstshash=Test"
    - ""  # empty cookie
  probe_response:
    ntlm_challenge: true        # respond to NTLM probes with fake challenge
    rdp_security_enum: true     # respond to security enumeration probes

logging:
  format: "json"
  file: "rdp-proxy.log"
  level: "info"
```

---

## Testing Plan

### TCP Fingerprint Tests

| # | Type | Test |
|---|------|------|
| 1 | Unit | SYN-ACK has TTL=128 |
| 2 | Unit | SYN-ACK has no TCP timestamp option |
| 3 | Unit | TCP window size is 65535 with scale 8 |
| 4 | Integration | nmap OS detection (`nmap -O`) reports Windows, not Linux |
| 5 | Integration | p0f passive fingerprint shows Windows signature |

### Certificate Tests

| # | Type | Test |
|---|------|------|
| 6 | Unit | Generated cert has CN matching configured hostname |
| 7 | Unit | Generated cert has Microsoft RDP Auth EKU OID |
| 8 | Unit | Generated cert is RSA 2048, SHA256WithRSA |
| 9 | Unit | Generated cert has ~180 day validity |
| 10 | Unit | Generated cert has 16-byte random serial number |
| 11 | Unit | Generated cert does NOT have BasicConstraints or AuthorityKeyID |
| 12 | Integration | `openssl s_client` shows cert matching Windows patterns |

### NTLM Probe Response Tests

| # | Type | Test |
|---|------|------|
| 13 | Unit | NTLM CHALLENGE has correct AV_PAIRs (all 6 fields) |
| 14 | Unit | MsvAvTimestamp is FILETIME format (correct epoch) |
| 15 | Unit | Product_Version matches configured OS version |
| 16 | Integration | `nmap --script rdp-ntlm-info` shows configured hostname, domain, OS version |

### Scanner Detection Tests

| # | Type | Test |
|---|------|------|
| 17 | Unit | `mstshash=nmap` detected as scanner probe |
| 18 | Unit | `mstshash=hello` detected as scanner probe |
| 19 | Unit | Empty cookie detected as scanner probe |
| 20 | Unit | `mstshash=Administrator` NOT detected as scanner (real client) |
| 21 | Integration | Scanner probe handled locally, not forwarded to PyRDP |
| 22 | Integration | Real client connection forwarded to PyRDP with PROXY protocol header |

### Proxy Forwarding Tests

| # | Type | Test |
|---|------|------|
| 23 | Integration | PROXY protocol v2 header sent to backend with correct client IP |
| 24 | Integration | Full RDP session through proxy → PyRDP → target succeeds |
| 25 | Integration | Bidirectional data forwarding works (client sends, server responds) |
| 26 | Integration | Connection teardown in either direction propagates correctly |

### Regression / Compatibility Tests

| # | Type | Test |
|---|------|------|
| 27 | Integration | PyRDP without proxy still works (direct connection) |
| 28 | Integration | Multiple concurrent connections through proxy |
| 29 | Integration | Large data transfers (file redirection, drive mapping) through proxy |

### Fingerprinting Validation (Manual / CI)

| # | Type | Test |
|---|------|------|
| 30 | Manual | Shodan scan of proxy shows Windows RDP, not honeypot |
| 31 | Manual | `rdp-sec-check` reports expected security configuration |
| 32 | Manual | Censys classification matches Windows RDP server |

---

## File Structure

```
rdp-proxy/
├── cmd/
│   └── rdp-proxy/
│       └── main.go              # CLI entry point, flag parsing
├── internal/
│   ├── config/
│   │   └── config.go            # YAML config parsing, defaults
│   ├── proxy/
│   │   ├── proxy.go             # TCP proxy core: accept, forward, PROXY protocol
│   │   └── proxy_test.go
│   ├── tcp/
│   │   ├── masquerade.go        # TCP socket options: TTL, timestamps, window
│   │   ├── masquerade_linux.go  # Linux-specific syscall implementations
│   │   └── masquerade_test.go
│   ├── cert/
│   │   ├── windows_cert.go      # Windows-style certificate generation
│   │   ├── windows_cert_test.go
│   │   └── store.go             # Certificate persistence and rotation
│   ├── ntlm/
│   │   ├── challenge.go         # NTLM CHALLENGE_MESSAGE builder with AV_PAIRs
│   │   ├── challenge_test.go
│   │   └── filetime.go          # Windows FILETIME conversion
│   ├── scanner/
│   │   ├── detect.go            # Scanner probe detection (cookie patterns, behavior)
│   │   ├── detect_test.go
│   │   ├── respond.go           # Fake responses for detected scanners
│   │   └── respond_test.go
│   └── proxyproto/
│       ├── v2.go                # PROXY protocol v2 header generation
│       └── v2_test.go
├── configs/
│   └── rdp-proxy.yaml           # Example config
├── Dockerfile
├── docker-compose.yml           # Example with PyRDP
├── go.mod
├── go.sum
└── Makefile
```

---

## Implementation Order

| Step | Component | Complexity | Description |
|------|-----------|------------|-------------|
| 1 | TCP proxy core | Low | Accept connections, bidirectional forwarding, PROXY protocol v2 to backend |
| 2 | TCP masquerading | Low | Socket options: TTL=128, disable timestamps, window size |
| 3 | Certificate generation | Low | Windows-style cert with proper CN, EKU, key usage, serial |
| 4 | NTLM challenge builder | Medium | CHALLENGE_MESSAGE with AV_PAIRs, FILETIME, Product_Version |
| 5 | Scanner detection | Medium | Cookie pattern matching, probe behavior identification |
| 6 | Scanner response handler | Medium | X224 + TLS + NTLM response for scanner probes |
| 7 | Config file support | Low | YAML parsing, CLI flags, defaults |
| 8 | Docker packaging | Low | Dockerfile, compose example with PyRDP |

Steps 1-3 can be done in parallel. Step 4-6 are the scanner handling chain. Step 7-8 are polish.

---

## Future Enhancements (v2)

- **TLS record packing:** Fork Go's `crypto/tls` to pack ServerHello+Certificate+ServerHelloDone into a single record. Defeats TLS Prober-level analysis.
- **Full TLS termination mode:** Terminate TLS at the proxy, re-encrypt to PyRDP. Enables full cipher suite control. Requires PyRDP changes to accept pre-terminated TLS.
- **RDP version spoofing:** Rewrite MCS Connect Response to match specific Windows versions. Requires partial RDP parsing in the proxy.
- **Timing normalization:** Add artificial latency to match expected Windows response timing profiles.
- **Multiple backend support:** Route different connections to different PyRDP instances.
- **Windows profile presets:** `--profile win10-2004`, `--profile server-2019`, `--profile server-2022` that set all parameters (version, ciphers, cert style, NTLM fields) consistently.
