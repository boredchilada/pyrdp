# RDP Honeypot Deployment Runbook

**Stack:** rdp-proxy (Go) + PyRDP (Python MITM) + Windows Server 2025 victim  
**Tested:** 2026-06-29  
**Status:** Verified working end-to-end with NLA/CredSSP passthrough

---

## Architecture

```
Internet → VPS (rdp-proxy :3389) → SSH reverse tunnel → PyRDP :13389 → Victim VM :3389
```

| Component | Role |
|-----------|------|
| **rdp-proxy** | Go binary on expendable VPS. Captures TLS ClientHello fingerprints, scanner NTLM hashes, forwards real connections via PROXY protocol v2 to PyRDP. |
| **PyRDP** | Python RDP MITM. NLA passthrough (CredSSP forwarded transparently), captures NTLM hashes in transit, records full sessions, logs keystrokes, captures clipboard and file transfers. |
| **Victim VM** | Windows machine with RDP enabled. Its RDP certificate must be exported and provided to PyRDP so CredSSP pubKeyAuth binding works. |

---

## 1. Victim VM Certificate Setup

The RDP certificate **MUST** have an exportable private key. Without this, PyRDP cannot present the same certificate to clients, and NLA/CredSSP pubKeyAuth binding will fail.

### Create and assign the certificate (PowerShell, run as Administrator)

```powershell
# Create exportable cert with RDP EKU
$cert = New-SelfSignedCertificate -DnsName "TARGET-HOSTNAME" `
  -CertStoreLocation "Cert:\LocalMachine\My" `
  -KeyExportPolicy Exportable `
  -KeySpec KeyExchange `
  -KeyLength 2048 `
  -NotAfter (Get-Date).AddYears(2) `
  -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.54.1.2")

# Set as RDP cert using WMI (correct method)
$ts = Get-CimInstance -Namespace "root/cimv2/TerminalServices" -ClassName Win32_TSGeneralSetting -Filter "TerminalName='RDP-Tcp'"
$ts | Set-CimInstance -Property @{SSLCertificateSHA1Hash = $cert.Thumbprint}

# Verify RDP still works BEFORE exporting!
# Connect to the victim VM with mstsc and confirm login succeeds.

# Export
Export-PfxCertificate -Cert $cert -FilePath C:\rdp-cert.pfx -Password (ConvertTo-SecureString "export" -Force -AsPlainText)
```

> **WARNING:** Do NOT use `Set-ItemProperty` on the registry key `SSLCertificateSHA1Hash`. The registry stores the thumbprint as raw bytes, but `Set-ItemProperty` writes a string. This silently breaks RDP with no useful error. Always use the CIM/WMI method shown above.

### Convert the certificate on the PyRDP machine

Transfer `rdp-cert.pfx` to the PyRDP host, then extract the PEM files:

```bash
# Extract certificate (public key)
openssl pkcs12 -in rdp-cert.pfx -out rdp-cert.pem -clcerts -nokeys -password pass:export

# Extract private key (unencrypted)
openssl pkcs12 -in rdp-cert.pfx -out rdp-key.pem -nocerts -nodes -password pass:export
```

Verify the fingerprint matches what the victim VM presents:

```bash
openssl x509 -in rdp-cert.pem -fingerprint -sha256 -noout
```

Compare this against the thumbprint shown in the Windows certificate store.

---

## 2. PyRDP Setup

### Install

```bash
cd pyrdp
python -m venv venv
./venv/Scripts/pip install -e .   # Windows
# or on Linux:
# ./venv/bin/pip install -e .
```

### Run

```bash
pyrdp-mitm <victim-ip>:3389 -l 13389 \
  --proxy-protocol \
  --auth tls,ssp \
  -c rdp-cert.pem \
  -k rdp-key.pem \
  -L INFO
```

### Flag reference

| Flag | Purpose |
|------|---------|
| `<victim-ip>:3389` | Target RDP server (the Windows VM) |
| `-l 13389` | Listen port for incoming MITM connections |
| `--proxy-protocol` | Expect PROXY protocol v2 header from rdp-proxy. Without this, PyRDP rejects connections from rdp-proxy. |
| `--auth tls,ssp` | Allow both TLS and CredSSP/NLA authentication methods |
| `-c rdp-cert.pem` | Victim's exported RDP certificate (public). **Must match** the victim's active RDP cert. |
| `-k rdp-key.pem` | Victim's exported RDP certificate (private key) |
| `-L INFO` | Log level. Use `DEBUG` for troubleshooting, `INFO` for production. |

---

## 3. rdp-proxy Setup (Go)

### Build

```bash
cd rdp-proxy
go build -o rdp-proxy ./cmd/rdp-proxy/
```

### Run on VPS

```bash
./rdp-proxy \
  -listen 0.0.0.0:3389 \
  -backend 127.0.0.1:13389 \
  -hostname TARGET-HOSTNAME \
  -domain TARGETDOMAIN \
  -os-build 26100 \
  -log-format json \
  -forward-all
```

### Flag reference

| Flag | Purpose |
|------|---------|
| `-listen 0.0.0.0:3389` | Public-facing listen address |
| `-backend 127.0.0.1:13389` | PyRDP address (via SSH tunnel) |
| `-hostname` | Hostname in NTLM challenge responses sent to scanners |
| `-domain` | Domain in NTLM challenge responses sent to scanners |
| `-os-build 26100` | Windows build number for NTLM VERSION bytes. `26100` = Server 2025. |
| `-log-format json` | Structured JSON logging for fleet ingestion |
| `-forward-all` | **Critical.** Forwards all connections including mstsc pre-auth probes. Without this, rdp-proxy handles some connections locally (scanner detection mode), which causes certificate mismatch when the client expects the victim's cert. |

---

## 4. SSH Reverse Tunnel

The tunnel makes PyRDP (on the internal network) reachable from the VPS without opening inbound firewall ports.

### Quick test

```bash
# From the PyRDP machine (outbound only, no firewall changes needed):
ssh -R 13389:localhost:13389 user@vps -N
```

rdp-proxy on the VPS sees the backend at `localhost:13389` via the tunnel.

### Production (autossh)

```bash
autossh -M 0 -f -N -R 13389:localhost:13389 user@vps \
  -o "ServerAliveInterval 30" \
  -o "ServerAliveCountMax 3"
```

`-M 0` disables autossh's monitoring port and relies on SSH's own keepalive (`ServerAliveInterval`) to detect dead connections. autossh restarts the tunnel automatically on failure.

### systemd unit (optional)

```ini
[Unit]
Description=autossh reverse tunnel for PyRDP
After=network-online.target
Wants=network-online.target

[Service]
User=tunnel
ExecStart=/usr/bin/autossh -M 0 -N -R 13389:localhost:13389 user@vps -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3"
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

---

## 5. Server 2025 Compatibility

Windows Server 2025 introduces a new MCS optimization. The server sets `RNS_UD_SC_SKIP_CHANNELJOIN_SUPPORTED` (`0x08`) in the MCS Connect Response `earlyCapabilityFlags`. This flag tells the client to skip MCS Channel Join Requests entirely and proceed directly to the Security Exchange.

**Problem:** PyRDP depends on Channel Join Confirms to build its MITM channel infrastructure. If the client skips Channel Joins, PyRDP never learns the channel mappings and the connection stalls (typically a 60-second timeout followed by disconnect).

**Solution (applied in our fork):** PyRDP strips the `0x08` flag from the MCS Connect Response before forwarding it to the client. The client then sends Channel Join Requests as usual. Since the server still expects the client to skip them, PyRDP responds with synthetic Channel Join Confirms locally instead of forwarding the requests to the server.

This is handled automatically. No configuration needed. If you see 60-second timeouts with no channel activity in DEBUG logs, verify the fork's `SKIP_CHANNELJOIN` patch is present.

---

## 6. Testing Checklist

Run these checks in order. Each step depends on the previous one working.

- [ ] **Direct RDP to victim works.** Open mstsc, connect to `<victim-ip>:3389`, log in. If this fails, fix the victim VM before continuing.
- [ ] **Certificate fingerprints match.** Run `openssl x509 -in rdp-cert.pem -fingerprint -sha256 -noout` and compare against the victim's cert thumbprint in `certlm.msc`.
- [ ] **PyRDP direct connection works.** Start PyRDP, connect mstsc to `<pyrdp-ip>:13389` (without rdp-proxy). Verify NLA completes and login succeeds. If NLA fails here, the cert is wrong.
- [ ] **Full chain works.** Start rdp-proxy on the VPS, open SSH tunnel, connect mstsc to `<vps-ip>:3389`. Verify login succeeds end-to-end.
- [ ] **Replay file created.** Check `pyrdp_output/replays/` for a non-zero `.pyrdp` file after the test session.
- [ ] **Login event logged.** Check `pyrdp_output/logs/mitm.json` for `login_success` events with correct username and client IP.
- [ ] **NTLM hash captured.** Check rdp-proxy JSON logs for NTLM hash entries from the test connection.

---

## 7. Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `0x904` ext `0x7` | pubKeyAuth mismatch. The certificate PyRDP presents does not match the victim's RDP certificate. CredSSP binds the TLS channel to the server's public key; a mismatch means the client detects tampering. | Re-export the victim's cert. Verify fingerprints match: `openssl x509 -in rdp-cert.pem -fingerprint -sha256 -noout` vs the thumbprint in `certlm.msc`. |
| `0x4` | Internal error. Channel setup failed during MCS negotiation. | Verify the `SKIP_CHANNELJOIN` fix is applied. Check PyRDP DEBUG logs for channel join activity. |
| 60s timeout then disconnect | Client Info PDU never arrives. Channels were not built because the client skipped Channel Joins. | The `SKIP_CHANNELJOIN` flag (`0x08`) is not being stripped. Verify the fork patch is present. |
| `tlsv1 alert internal error` | CredSSP forwarding failed. The cert/key pair loaded by PyRDP is invalid or does not match. | Re-export the victim's cert and key. Verify `openssl x509 -in rdp-cert.pem -noout -modulus` matches `openssl rsa -in rdp-key.pem -noout -modulus`. |
| Connection works but no keystroke capture | Modern mstsc may use the dynamic virtual channel (`drdynvc`) for input rather than the static input PDU channel. | Known limitation of keystroke interception. The replay file (`.pyrdp`) still captures everything via the graphics channel. |
| `PROXY protocol header not found` | PyRDP received a connection without PROXY v2 header but `--proxy-protocol` is enabled. | Either the client connected directly to PyRDP (bypassing rdp-proxy), or rdp-proxy is not sending PROXY headers. Verify rdp-proxy is running and the tunnel is up. |
| RDP broken after cert change on victim | Used `Set-ItemProperty` on registry `SSLCertificateSHA1Hash` instead of the CIM method. | Use the CIM/WMI method shown in Section 1. The registry stores the thumbprint as raw bytes; `Set-ItemProperty` writes a string, silently corrupting it. |

---

## 8. What Gets Captured

### Pre-authentication (every connection, including scanners)

| Data | Source |
|------|--------|
| NTLM hash (hashcat/john ready) | rdp-proxy NTLM challenge/response |
| Client OS version | NTLM `VERSION` bytes |
| Client workstation name | NTLM `Workstation` field |
| NTLM negotiate flags | NTLM `NEGOTIATE_MESSAGE` |
| TLS ClientHello fingerprint | rdp-proxy TLS interception (cipher suites, curves, extensions) |
| X.224 requested protocols | RDP negotiation request (`PROTOCOL_RDP`, `PROTOCOL_SSL`, `PROTOCOL_HYBRID`) |
| Connection timing | rdp-proxy timestamps |

### Post-authentication (successful logins only)

| Data | Source |
|------|--------|
| Full session replay (`.pyrdp` file) | PyRDP graphics + input capture |
| Username, domain, client IP | Client Info PDU / PROXY v2 header |
| Client hostname, OS build | Client Core Data |
| Keyboard layout, screen resolution | Client Core Data |
| Channel list | MCS Channel Join (`rdpdr`, `cliprdr`, `rdpsnd`, `drdynvc`, etc.) |
| Clipboard content | `cliprdr` channel interception |
| File transfers (drive redirection) | `rdpdr` channel interception |
| Device mapping (printers, smart cards) | `rdpdr` device announce |

### Output locations

```
pyrdp_output/
  replays/        # .pyrdp session replay files
  logs/
    mitm.json     # structured MITM event log
    mitm.log      # human-readable log
  filesystems/    # files transferred via drive redirection
  certs/          # captured certificates
```

Replay files can be viewed with:

```bash
pyrdp-player pyrdp_output/replays/<file>.pyrdp
```

---

## 9. Operational Notes

- **rdp-proxy is expendable.** If the VPS is compromised, the attacker gains nothing beyond the Go binary and its logs. No credentials, no access to the internal network. The SSH tunnel is outbound-only from the PyRDP machine.
- **Rotate the victim VM periodically.** Attackers who gain RDP access will leave artifacts. Snapshot before deployment, revert when dirty.
- **Monitor disk space.** Replay files grow with session length. A 30-minute session can produce 50-100 MB of replay data. Set up log rotation or periodic cleanup.
- **NLA is required.** The entire CredSSP passthrough chain depends on NLA being enabled on the victim. Do not disable NLA "to make things easier" -- it breaks the cert binding that makes this work.
- **PROXY protocol is not optional.** rdp-proxy sends PROXY v2 headers. PyRDP must be started with `--proxy-protocol`. Without it, PyRDP interprets the PROXY header as malformed RDP data and drops the connection.
