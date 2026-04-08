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
    family: str
    command: str
    rawLength: int


def parseV1(data: bytes) -> ProxyProtocolHeader:
    """Parse a PROXY protocol v1 (text) header."""
    crlf = data.find(b'\r\n')
    if crlf == -1:
        if len(data) >= V1_MAX_LENGTH:
            raise ValueError("PROXY v1 header exceeds 107 bytes without CRLF")
        raise ValueError("Incomplete PROXY v1 header: no CRLF found")

    line = data[:crlf].decode('ascii')
    rawLength = crlf + 2

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
