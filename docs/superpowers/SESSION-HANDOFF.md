# Session Handoff: CredSSP Session Bridging (Task 12)

## Copy this entire file as the prompt for the next Claude Code session.

---

## Context

I'm working on a PyRDP fork (RDP Monster-in-the-Middle tool) at `F:/laboratory/Honeypot-General/pyrdp/pyrdp`. Branch: `feature/proxy-protocol-nla`.

I've implemented CredSSP/NLA authentication so PyRDP can MITM connections to NLA-enforcing RDP servers. The CredSSP exchange itself works perfectly — validated against a real Windows domain controller. But there's a **race condition** that prevents the full RDP session from establishing after CredSSP completes.

## What's Working (DO NOT TOUCH)

These are done, tested, committed. Don't modify unless you need to fix the race condition:

- **PROXY protocol v1/v2** — `--proxy-protocol` flag, parser in `pyrdp/core/proxy_protocol.py`, TCP buffering in `pyrdp/layer/tcp.py`
- **Clean NLA hash capture** — `--nla-fallback`, TSRequest error response in `pyrdp/security/nla.py`
- **CredSSP client** — NTLM computation, SPNEGO wrapping, TSRequest serialization in `pyrdp/security/credssp.py`
- **40 unit tests** in `test/test_proxy_protocol.py`, `test/test_credssp_client.py`, `test/test_nla_improvements.py`

## The Problem: MCS/CredSSP Race Condition

### The flow that works:
```
1. Client → PyRDP: X224 Connection Request (TLS+NLA)
2. PyRDP → Server: X224 Connection Request (TLS only, downgrade)
3. Server → PyRDP: HYBRID_REQUIRED_BY_SERVER (NLA required)
4. PyRDP disconnects from server
5. PyRDP reconnects to server WITH CredSSP enabled
6. Both TLS tunnels established (client↔PyRDP and PyRDP↔server)
7. PyRDP → Server: CredSSP NEGOTIATE → CHALLENGE → AUTHENTICATE + pubKeyAuth → TSCredentials
8. Server accepts CredSSP ✓
```

### Where it breaks:
```
9. Client sends MCS Connect Initial (TPKT data) to PyRDP
   (client thinks it's a TLS-only connection, no NLA needed)
10. PyRDP's normal MITM layers forward MCS to server
11. Server REJECTS it → [SSL: TLSV1_ALERT_INTERNAL_ERROR]
```

The MCS data from the client arrives at PyRDP ~25ms after CredSSP step 7 is sent but BEFORE CredSSP step 8 (server confirmation) completes. The `_performServerCredSSP()` method in RDPMITM.py is an async coroutine that awaits the server response, but meanwhile the Twisted reactor delivers the client's MCS data which gets forwarded to the server too early.

### Evidence from logs:
```
15:27:57,983 - credssp - Server TLS public key: 270 bytes
15:27:58,010 - mcs - Client hostname MAINDOOK          ← MCS arrives during CredSSP!
15:27:58,014 - tcp - Server connection closed. [('SSL routines', '', 'tlsv1 alert internal error')]
```

The MCS Connect Initial and the CredSSP pubKeyAuth confirmation arrive within 4ms of each other.

### What was tried and failed:
- `transport.pauseProducing()` on client TCP — froze the entire reactor, server responses stopped arriving too
- `asyncio.sleep(0.5)` after CredSSP — race condition still wins

## The File to Fix

**`pyrdp/mitm/RDPMITM.py`** — specifically the `_performServerCredSSP()` method (around line 261) and the `doClientTls()` method (around line 220).

The method `_performServerCredSSP()` is an async coroutine that:
1. Gets the server TLS cert/public key
2. Installs a temporary `CredSSPResponseHandler` on `self.server.segmentation` to intercept server CredSSP responses
3. Sends NTLM NEGOTIATE via `self.server.tcp.sendBytes()`
4. Awaits server CHALLENGE from the response queue
5. Sends AUTHENTICATE + pubKeyAuth
6. Awaits server pubKeyAuth confirmation
7. Sends TSCredentials
8. Removes the handler

The problem is that between steps 7 and 8 (or after 8), client MCS data arrives and gets forwarded to the server's TPKT layer, which sends it over the server TLS connection. The server hasn't finished processing CredSSP yet.

## What Needs to Happen

The client-to-server data forwarding path must be **blocked during CredSSP and released after**. Specifically:

1. When CredSSP starts: prevent any client TPKT/FastPath data from being forwarded to the server
2. When CredSSP completes: allow buffered client data to flow to the server

### Possible approaches to investigate:

**A) Intercept at the server segmentation layer**
The server's `SegmentationLayer` routes data by header byte. TPKT (0x03) goes to the TPKT layer. Unknown headers (0x30 for CredSSP TSRequest) go to `onUnknownHeader`. During CredSSP, temporarily remove or disable the TPKT route so any MCS data from the client that gets forwarded just buffers in the segmentation layer.

**B) Intercept at the MCSMITM or X224MITM level**
The `MCSMITM` component forwards MCS Connect Initial from client to server. Add a flag `self.state.credSSPInProgress` that makes MCSMITM buffer MCS data instead of forwarding it.

**C) Intercept at the TCP layer**
The server's `TwistedTCPLayer.sendBytes()` is what ultimately writes to the server TLS connection. Override or wrap `sendBytes()` during CredSSP to queue outbound data instead of sending it.

**D) Restructure the flow**
Instead of running CredSSP as a separate async coroutine while the normal MITM flow continues, change the architecture so the MITM flow is gated. After TLS setup, enter a "CredSSP phase" where the server connection handles CredSSP exclusively, then transition to "MCS phase" where normal MITM forwarding begins.

## Key Files to Read

Before implementing a fix, read and understand these files:

1. **`pyrdp/mitm/RDPMITM.py`** — The orchestrator. Read `doClientTls()`, `_performServerCredSSP()`, `startTLS()`, `connectToServer()`, `buildIOChannel()`
2. **`pyrdp/mitm/X224MITM.py`** — Read `onConnectionRequest()` and `onConnectionConfirm()` to understand the X224 negotiation replay when NLA is required
3. **`pyrdp/mitm/TCPMITM.py`** — Read `onClientConnection()`, `onServerConnection()`
4. **`pyrdp/layer/tcp.py`** — Read `TwistedTCPLayer.dataReceived()` and `sendBytes()` — this is where raw data enters and leaves
5. **`pyrdp/layer/segmentation.py`** — Read `SegmentationLayer.recv()` — this routes TPKT vs FastPath vs unknown (NLA) headers
6. **`pyrdp/mitm/MCSMITM.py`** — MCS layer MITM that forwards MCS Connect Initial
7. **`pyrdp/mitm/state.py`** — State fields including `serverRequiresNLA`, `ntlmCapture`

## RDP Protocol Flow Reference

After CredSSP completes, the RDP protocol continues with the standard MCS/GCC sequence. The server expects this exact order:

```
Phase 1: Connection Initiation (DONE — X224 level)
  Client → Server: X224 Connection Request
  Server → Client: X224 Connection Confirm
  [TLS Handshake]
  [CredSSP Exchange — our new code handles this]

Phase 2: Basic Settings Exchange (THIS IS WHERE IT BREAKS)
  Client → Server: MCS Connect Initial (contains GCC Conference Create Request)
    - Includes: Client Core Data, Client Security Data, Client Network Data
    - TPKT header (0x03) + X224 Data header + MCS CI payload
  Server → Client: MCS Connect Response (contains GCC Conference Create Response)
    - Includes: Server Core Data, Server Security Data, Server Network Data

Phase 3: Channel Connection
  Client → Server: MCS Erect Domain Request
  Client → Server: MCS Attach User Request
  Server → Client: MCS Attach User Confirm
  Client → Server: MCS Channel Join Request (repeated per channel)
  Server → Client: MCS Channel Join Confirm (repeated per channel)

Phase 4: RDP Security Commencement
  Client → Server: Security Exchange PDU (if not using TLS)
  Client → Server: Client Info PDU (contains username, password, domain)
  Server → Client: Server License PDU
  Server → Client: Demand Active PDU (capabilities)
  Client → Server: Confirm Active PDU

Phase 5: Session
  [Normal RDP I/O — FastPath and SlowPath PDUs]
```

The key insight: the server transitions from "CredSSP mode" (reading TSRequest BER data) to "RDP mode" (reading TPKT-framed data) after receiving TSCredentials. There may be a brief period where the server is processing credentials and not yet ready for TPKT. Our 0.5s sleep wasn't enough, OR the issue is that TPKT data arrived before TSCredentials was even sent (the race).

## Test Server

- **IP:** 10.99.40.34
- **Domain:** cyberox.ca (NetBIOS: CYBEROX)
- **Username:** d.osei
- **Password:** Adm1n@Cyb3r0x#1
- **NLA:** Enforced (HYBRID_REQUIRED)

## How to Test

```bash
# Activate venv
cd F:/laboratory/Honeypot-General/pyrdp/pyrdp

# Run unit tests (should all pass)
./venv/Scripts/python -m pytest test/test_proxy_protocol.py test/test_credssp_client.py test/test_nla_improvements.py -v

# Run PyRDP MITM against NLA server
./venv/Scripts/python -m pyrdp.bin.mitm 10.99.40.34:3389 -l 33389 -u d.osei -p "Adm1n@Cyb3r0x#1" -L DEBUG

# Connect with mstsc (use the RDP file on desktop)
# C:\Users\dookie\Desktop\pyrdp-test.rdp (points to 127.0.0.1:33389)

# Run the standalone CredSSP test (proves CredSSP itself works)
./venv/Scripts/python test/test_credssp_live.py 10.99.40.34 cyberox.ca d.osei "Adm1n@Cyb3r0x#1"
```

## Codebase Conventions

- **camelCase** naming (not snake_case)
- 120 char line limit
- Python 3 type hints
- **%-style formatting for log statements**: `self.log.info("message %(var)s", {"var": value})`
- f-strings for everything else
- **Do NOT add Co-Authored-By to commits**
- Run `./venv/Scripts/python -m pytest test/test_proxy_protocol.py test/test_credssp_client.py test/test_nla_improvements.py -q` after changes to verify no regressions

## Dependencies

The CredSSP implementation uses `impacket` for NTLM SEAL/SIGN (impacket's `ntlm.SEAL()`, `ntlm.SIGNKEY()`, `ntlm.SEALKEY()`, `ntlm.getNTLMSSPType1()`, `ntlm.getNTLMSSPType3()`). This is already installed in the venv. Key finding: our homebrew GSS_WrapEx didn't work correctly for extended session security — impacket's SEAL handles the per-message re-keying properly.

## Success Criteria

1. Start PyRDP with `-u d.osei -p "Adm1n@Cyb3r0x#1"` targeting `10.99.40.34:3389`
2. Connect with mstsc through PyRDP
3. See the Windows login screen (or desktop if auto-login works)
4. PyRDP logs show: CredSSP complete → MCS Connect → Channel Join → Client Info → Session active
5. Replay file is saved and playable with `pyrdp-player`
