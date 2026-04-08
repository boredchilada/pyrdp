# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyRDP is a Python RDP (Remote Desktop Protocol) Monster-in-the-Middle tool and library by GoSecure. It intercepts RDP connections, logs credentials, steals clipboard/files, records sessions, and supports replay/conversion. Version 2.1.1.dev0, GPLv3+, Python 3.7–3.13.

## Build & Install

```bash
# Slim install (MITM/CLI only)
pip install -U -e .

# Full install (includes GUI player and video conversion)
pip install -U -e ".[full]"

# C extension (RLE compression) is built automatically via setup.py
```

## Testing

```bash
# Unit tests
python -m unittest discover -v

# CredSSP/NLA-specific tests (run from venv)
./venv/Scripts/python -m pytest test/test_proxy_protocol.py test/test_credssp_client.py test/test_nla_improvements.py -v

# Live NLA MITM test (requires NLA-enforcing server)
./venv/Scripts/python -m pyrdp.bin.mitm <target>:3389 -l 33389 -u <user> -p <pass> -L DEBUG

# Integration tests (require test files extracted first)
# Extract: unzip test/files/test_files.zip -d test/files && unzip test/files/test_convert_428.zip -d test/files
python test/test_prerecorded.py
python test/test_mitm_initialization.py dummy_value
./test/integration.sh

# Coverage (CI enforces 40% minimum)
coverage run -m unittest discover -v
coverage report --fail-under=40
```

## Linting

Flake8 with max-line-length 120. Config in `.flake8`.

## Docker

```bash
docker build -t pyrdp .                        # Full image (GUI + video)
docker build -f Dockerfile.slim -t pyrdp .      # Slim image (CLI only)
```

## Entry Points

| Command | Module | Purpose |
|---------|--------|---------|
| `pyrdp-mitm` | `pyrdp.bin.mitm` | MITM server |
| `pyrdp-player` | `pyrdp.bin.player` | Replay viewer (GUI/headless) |
| `pyrdp-convert` | `pyrdp.bin.convert` | Replay→video/JSON, PCAP→replay |
| `pyrdp-clonecert` | `pyrdp.bin.clonecert` | Clone RDP server certificates |

## PROXY Protocol

When running behind nginx/HAProxy/AWS NLB, use `--proxy-protocol` to have PyRDP
read PROXY protocol v1/v2 headers and log the real client IP instead of the proxy's IP.

```bash
pyrdp-mitm 192.168.1.100:3389 --proxy-protocol
```

## Architecture

### Layer-Based Protocol Stack

The core design is an event-driven layer stack mirroring the RDP protocol:

```
TCP → Segmentation (TPKT / FastPath) → X224 → MCS → Security → I/O / Virtual Channels
```

Each layer parses its PDU and forwards data to the next layer. Special PDUs (connection, disconnection, errors) are handled via the **Observer pattern** — layers emit events to attached `LayerObserver` instances rather than forwarding.

MCS is where the stack branches: after MCS, traffic splits by channel (I/O, clipboard, drive redirection, etc.) via `MCSRouter` and `ChannelFactory`.

### Key Package Layout

- **`pyrdp/core/`** — Foundational abstractions: BER/PER encoding (`ber.py`, `per.py`), Observer pattern (`observer.py`, `event.py`), byte stream handling (`stream.py`), SSL/TLS (`ssl.py`)
- **`pyrdp/layer/`** — Protocol layer implementations (TCP, TPKT, X224, MCS, FastPath, SlowPath, Security, virtual channels)
- **`pyrdp/parser/`** — Packet parsers that decode raw bytes into PDUs
- **`pyrdp/pdu/`** — Protocol Data Unit dataclass definitions for all RDP message types
- **`pyrdp/enum/`** — RDP protocol constants and enumerations
- **`pyrdp/mitm/`** — MITM interception logic, composed per-connection as: `TCPMITM` → `X224MITM` → `MCSMITM` → `RDPMITM`, with pluggable modules (`SecurityMITM`, `ClipboardMITM`, `DeviceRedirectionMITM`, `FileCrawlerMITM`)
- **`pyrdp/security/`** — Cryptography: RC4, TLS, NLA/CredSSP, NTLMSSP, key derivation
- **`pyrdp/player/`** — Qt-based GUI replay player and headless mode
- **`pyrdp/convert/`** — Format converters (PCAP↔replay↔video↔JSON)
- **`pyrdp/recording/`** — Session recording and `.pyrdp` replay format
- **`pyrdp/bin/`** — CLI entry points

### MITM Connection Flow

`MITMServerFactory` spawns per-connection handler chains. Each MITM module intercepts traffic at its protocol layer, can inspect/modify/record PDUs, then forwards to the real server. `MITMRecorder` captures events into `.pyrdp` replay files. Config is in `mitm.default.ini`.

### Networking

Built on **Twisted** for async I/O. The `twisted/` directory at repo root contains Twisted plugin support.

## Code Style (from CONTRIBUTING.md)

- PEP8 with **camelCase** naming convention (not snake_case)
- 120 character line limit
- Python 3 type hints (not reStructuredText-style)
- f-strings or `str.format()` for string formatting
- **%-style formatting for log statements only** (for analysis purposes): `logging.info("Hello %(who)s!", {"who": "World"})`
- Docstrings in reStructuredText syntax

## NLA/CredSSP Architecture

When the server enforces NLA (`HYBRID_REQUIRED_BY_SERVER`), PyRDP performs CredSSP on behalf of the client:

1. X224MITM detects `HYBRID_REQUIRED`, sets `state.serverRequiresNLA`, reconnects with CredSSP
2. Client is told `selectedProtocol=SSL` (no NLA needed from client's perspective)
3. RDPMITM._performServerCredSSP() runs CredSSP as async coroutine using impacket's NTLM
4. Client data is **gated** at the segmentation layer during CredSSP to prevent race conditions
5. MCSMITM.onConnectInitial() patches `serverSelectedProtocol` from SSL→CREDSSP before forwarding
6. After CredSSP + 0.5s delay, gated client data is replayed and normal MITM flow resumes

Key files: `RDPMITM.py` (_performServerCredSSP), `X224MITM.py` (onConnectionConfirm), `MCSMITM.py` (onConnectInitial), `security/credssp.py`

## Windows Operational Notes

- **One MITM instance at a time when testing** — multiple instances can cause server-side CredSSP session conflicts from the same source IP
- **Port reuse after kill**: `SO_REUSEADDR` is not set on Windows; forcefully killed processes leave sockets in TIME_WAIT. Wait a few seconds or use a different port
- **Kill by PID, not by process name**: `taskkill /F /PID <pid>` — don't `taskkill /F /IM python.exe` as it kills unrelated Python processes
