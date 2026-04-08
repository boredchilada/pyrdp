#!/usr/bin/env python3
"""
Live integration test: Full CredSSP authentication against a real NLA-enforcing RDP server.
This validates the entire chain: X224 negotiation, TLS, NTLM computation, SPNEGO, TSRequest, pubKeyAuth.

Usage:
    python test/test_credssp_live.py <host> <domain> <username> <password>
"""

import hashlib
import os
import socket
import ssl
import struct
import sys
import time
from io import BytesIO

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyrdp.security.credssp import (
    ntowfv2, computeNTLMv2Response, computeSessionBaseKey,
    generateExportedSessionKey, computeSignKey, computeSealKey,
    gssWrapEx, computePubKeyAuth,
    buildSpnegoNegTokenInit, buildSpnegoNegTokenResp,
    buildTSRequest, buildTSCredentials,
    _hmacMd5,
)
from pyrdp.core import ber, Uint16LE, Uint32LE, Uint8


def buildX224ConnectionRequest(requestedProtocols: int = 0x03) -> bytes:
    """Build X224 Connection Request with NLA+TLS requested."""
    # RDP Negotiation Request: type(1) + flags(1) + length(2) + protocols(4)
    negReq = struct.pack('<BBHI', 0x01, 0x00, 0x0008, requestedProtocols)

    # X224 CR TPDU: LI includes everything after LI byte
    # type(1) + dst_ref(2) + src_ref(2) + class(1) + negReq = 6 + len(negReq)
    variableData = struct.pack('>BHBB', 0xE0, 0x0000, 0x00, 0x00) + negReq
    li = len(variableData) + 1  # +1 for the dst_ref high byte that's part of the header

    # Actually, just build it correctly: LI = total TPDU length - 1 (LI itself excluded)
    tpdu = struct.pack('>B', 0xE0) + b'\x00\x00' + b'\x00\x00' + b'\x00' + negReq
    li = len(tpdu)

    # TPKT: version(1) + reserved(1) + length(2)
    pktLen = 4 + 1 + len(tpdu)  # TPKT(4) + LI(1) + TPDU
    tpkt = struct.pack('>BBH', 0x03, 0x00, pktLen)

    return tpkt + struct.pack('>B', li) + tpdu


def parseX224ConnectionConfirm(data: bytes) -> dict:
    """Parse X224 Connection Confirm to extract selected protocol."""
    result = {}
    # TPKT: version(1) + reserved(1) + length(2)
    tpktLen = struct.unpack('>H', data[2:4])[0]
    # X224 CC: length(1) + type(1) + dst(2) + src(2) + class(1)
    x224Type = data[5] >> 4
    result['type'] = x224Type

    # Check for negotiation response (at end of packet)
    if len(data) >= tpktLen:
        negStart = tpktLen - 8
        if negStart > 4 and data[negStart] in (0x02, 0x03):  # NEG_RSP or NEG_FAILURE
            result['negType'] = data[negStart]
            result['negFlags'] = data[negStart + 1]
            result['selectedProtocol'] = struct.unpack('<I', data[negStart + 4:negStart + 8])[0]

    return result


def parseTSRequest(data: bytes) -> dict:
    """Parse a TSRequest to extract version, negoTokens, pubKeyAuth, errorCode."""
    result = {}
    stream = BytesIO(data)

    # SEQUENCE tag
    tag = stream.read(1)[0]
    if tag != 0x30:
        raise ValueError(f"Expected SEQUENCE (0x30), got 0x{tag:02x}")

    # Length
    length = _readBerLength(stream)

    # Read fields by contextual tag
    while stream.tell() < len(data):
        pos = stream.tell()
        if pos >= len(data):
            break
        fieldTag = stream.read(1)
        if not fieldTag:
            break
        fieldTag = fieldTag[0]
        fieldLen = _readBerLength(stream)
        fieldData = stream.read(fieldLen)

        ctxTag = fieldTag & 0x1F

        if ctxTag == 0:  # version
            s = BytesIO(fieldData)
            s.read(1)  # INTEGER tag
            intLen = _readBerLength(s)
            result['version'] = int.from_bytes(s.read(intLen), 'big')

        elif ctxTag == 1:  # negoTokens
            # Dig through SEQUENCE OF SEQUENCE { [0] OCTET STRING }
            result['negoTokens'] = _extractNegoToken(fieldData)

        elif ctxTag == 3:  # pubKeyAuth
            s = BytesIO(fieldData)
            s.read(1)  # OCTET STRING tag
            oLen = _readBerLength(s)
            result['pubKeyAuth'] = s.read(oLen)

        elif ctxTag == 4:  # errorCode
            s = BytesIO(fieldData)
            s.read(1)  # INTEGER tag
            intLen = _readBerLength(s)
            result['errorCode'] = int.from_bytes(s.read(intLen), 'big')

    return result


def _readBerLength(stream: BytesIO) -> int:
    """Read a BER length field."""
    b = stream.read(1)[0]
    if b < 128:
        return b
    elif b == 0x81:
        return stream.read(1)[0]
    elif b == 0x82:
        return struct.unpack('>H', stream.read(2))[0]
    elif b == 0x83:
        return int.from_bytes(stream.read(3), 'big')
    else:
        raise ValueError(f"Unsupported BER length encoding: 0x{b:02x}")


def _extractNegoToken(data: bytes) -> bytes:
    """Extract the actual token bytes from negoTokens wrapping."""
    # Walk through SEQUENCE OF SEQUENCE { [0] OCTET STRING { token } }
    stream = BytesIO(data)
    # Outer SEQUENCE
    stream.read(1)
    _readBerLength(stream)
    # Inner SEQUENCE
    stream.read(1)
    _readBerLength(stream)
    # [0] contextual
    stream.read(1)
    _readBerLength(stream)
    # OCTET STRING
    stream.read(1)
    tokenLen = _readBerLength(stream)
    return stream.read(tokenLen)


def parseNTLMChallenge(data: bytes) -> dict:
    """Parse NTLM CHALLENGE_MESSAGE from SPNEGO-wrapped response."""
    result = {}

    # Find NTLMSSP signature
    idx = data.find(b'NTLMSSP\x00')
    if idx == -1:
        raise ValueError("No NTLMSSP signature found in challenge")

    stream = BytesIO(data[idx:])
    sig = stream.read(8)  # NTLMSSP\x00
    msgType = struct.unpack('<I', stream.read(4))[0]
    if msgType != 2:
        raise ValueError(f"Expected CHALLENGE (2), got {msgType}")

    # TargetNameFields
    targetNameLen = struct.unpack('<H', stream.read(2))[0]
    targetNameMaxLen = struct.unpack('<H', stream.read(2))[0]
    targetNameOffset = struct.unpack('<I', stream.read(4))[0]

    negotiateFlags = struct.unpack('<I', stream.read(4))[0]
    result['negotiateFlags'] = negotiateFlags

    serverChallenge = stream.read(8)
    result['serverChallenge'] = serverChallenge

    reserved = stream.read(8)

    # TargetInfoFields
    targetInfoLen = struct.unpack('<H', stream.read(2))[0]
    targetInfoMaxLen = struct.unpack('<H', stream.read(2))[0]
    targetInfoOffset = struct.unpack('<I', stream.read(4))[0]

    # Version
    version = stream.read(8)
    result['version'] = version

    # Extract TargetInfo from the raw message
    rawMsg = data[idx:]
    if targetInfoOffset > 0 and targetInfoLen > 0:
        result['targetInfo'] = rawMsg[targetInfoOffset:targetInfoOffset + targetInfoLen]
    else:
        result['targetInfo'] = b''

    return result


def buildNTLMNegotiate() -> bytes:
    """Build NTLMSSP NEGOTIATE_MESSAGE."""
    flags = (
        0x00000001 |  # NEGOTIATE_UNICODE
        0x00000002 |  # NEGOTIATE_OEM
        0x00000008 |  # REQUEST_TARGET
        0x00000010 |  # NEGOTIATE_SIGN
        0x00000020 |  # NEGOTIATE_SEAL
        0x00000200 |  # NEGOTIATE_NTLM
        0x00008000 |  # NEGOTIATE_ALWAYS_SIGN
        0x00080000 |  # NEGOTIATE_EXTENDED_SESSIONSECURITY
        0x02000000 |  # NEGOTIATE_128
        0x20000000 |  # NEGOTIATE_KEY_EXCH
        0x80000000    # NEGOTIATE_56
    )

    msg = bytearray()
    msg.extend(b'NTLMSSP\x00')
    msg.extend(struct.pack('<I', 1))  # NEGOTIATE_MESSAGE
    msg.extend(struct.pack('<I', flags))
    # DomainNameFields (empty)
    msg.extend(struct.pack('<HHI', 0, 0, 0))
    # WorkstationFields (empty)
    msg.extend(struct.pack('<HHI', 0, 0, 0))
    # Version (10.0.19041, NTLM revision 15)
    msg.extend(struct.pack('<BBHBBBB', 10, 0, 19041, 0, 0, 0, 15))

    return bytes(msg)


def buildNTLMAuthenticate(user: str, domain: str, password: str,
                           serverChallenge: bytes, targetInfo: bytes,
                           negotiateFlags: int) -> tuple:
    """
    Build NTLMSSP AUTHENTICATE_MESSAGE.
    Returns (authenticateMessage, exportedSessionKey).
    """
    # Compute response key
    responseKey = ntowfv2(password, user, domain)

    # Client challenge
    clientChallenge = os.urandom(8)

    # Extract timestamp from targetInfo, or use current time
    timestamp = _extractTimestamp(targetInfo)
    if timestamp is None:
        # Generate FILETIME for now
        import datetime
        EPOCH_DIFF = 116444736000000000
        now = int(time.time() * 10000000) + EPOCH_DIFF
        timestamp = struct.pack('<Q', now)

    # Compute NTLMv2 response
    ntProofStr, ntChallengeResponse = computeNTLMv2Response(
        responseKey, serverChallenge, clientChallenge, timestamp, targetInfo
    )

    # Session key
    sessionBaseKey = computeSessionBaseKey(responseKey, ntProofStr)
    exportedKey, encryptedRandomSessionKey = generateExportedSessionKey(sessionBaseKey)

    # Build the message
    domainBytes = domain.encode('utf-16-le')
    userBytes = user.encode('utf-16-le')
    workstationBytes = b''  # empty
    lmResponse = b'\x00' * 24  # Empty LM response

    # Calculate offsets (after fixed header)
    fixedLen = 88  # 8(sig) + 4(type) + 6*8(fields) + 4(flags) + 8(version) + 16(MIC)
    offset = fixedLen
    lmOffset = offset
    offset += len(lmResponse)
    ntOffset = offset
    offset += len(ntChallengeResponse)
    domainOffset = offset
    offset += len(domainBytes)
    userOffset = offset
    offset += len(userBytes)
    workstationOffset = offset
    offset += len(workstationBytes)
    encKeyOffset = offset

    flags = negotiateFlags | 0x20000000  # Ensure KEY_EXCH

    msg = bytearray()
    msg.extend(b'NTLMSSP\x00')
    msg.extend(struct.pack('<I', 3))  # AUTHENTICATE_MESSAGE

    # LmChallengeResponseFields
    msg.extend(struct.pack('<HHI', len(lmResponse), len(lmResponse), lmOffset))
    # NtChallengeResponseFields
    msg.extend(struct.pack('<HHI', len(ntChallengeResponse), len(ntChallengeResponse), ntOffset))
    # DomainNameFields
    msg.extend(struct.pack('<HHI', len(domainBytes), len(domainBytes), domainOffset))
    # UserNameFields
    msg.extend(struct.pack('<HHI', len(userBytes), len(userBytes), userOffset))
    # WorkstationFields
    msg.extend(struct.pack('<HHI', len(workstationBytes), len(workstationBytes), workstationOffset))
    # EncryptedRandomSessionKeyFields
    msg.extend(struct.pack('<HHI', len(encryptedRandomSessionKey), len(encryptedRandomSessionKey), encKeyOffset))

    # NegotiateFlags
    msg.extend(struct.pack('<I', flags))

    # Version (8 bytes)
    msg.extend(struct.pack('<BBHBBBB', 10, 0, 19041, 0, 0, 0, 15))

    # MIC (16 bytes, zeros for now — computed later if needed)
    msg.extend(b'\x00' * 16)

    # Payload
    msg.extend(lmResponse)
    msg.extend(ntChallengeResponse)
    msg.extend(domainBytes)
    msg.extend(userBytes)
    msg.extend(workstationBytes)
    msg.extend(encryptedRandomSessionKey)

    return bytes(msg), exportedKey


def _extractNetBIOSDomain(targetInfo: bytes) -> str:
    """Extract MsvAvNbDomainName from TargetInfo AV_PAIRs."""
    stream = BytesIO(targetInfo)
    while stream.tell() < len(targetInfo):
        avId = struct.unpack('<H', stream.read(2))[0]
        avLen = struct.unpack('<H', stream.read(2))[0]
        avValue = stream.read(avLen)
        if avId == 0x0002:  # MsvAvNbDomainName
            return avValue.decode('utf-16-le')
        if avId == 0x0000:  # MsvAvEOL
            break
    return None


def _extractTimestamp(targetInfo: bytes) -> bytes:
    """Extract MsvAvTimestamp from TargetInfo AV_PAIRs."""
    stream = BytesIO(targetInfo)
    while stream.tell() < len(targetInfo):
        avId = struct.unpack('<H', stream.read(2))[0]
        avLen = struct.unpack('<H', stream.read(2))[0]
        avValue = stream.read(avLen)
        if avId == 0x0007:  # MsvAvTimestamp
            return avValue
        if avId == 0x0000:  # MsvAvEOL
            break
    return None


def recvAll(sock, timeout=10.0) -> bytes:
    """Receive data from socket with a single blocking recv."""
    import time
    sock.settimeout(timeout)
    time.sleep(0.5)  # Give server time to respond
    try:
        data = sock.recv(16384)
        return data if data else b''
    except (socket.timeout, ssl.SSLError, OSError):
        return b''


def main():
    if len(sys.argv) != 5:
        print(f"Usage: {sys.argv[0]} <host> <domain> <username> <password>")
        sys.exit(1)

    host = sys.argv[1]
    domain = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]
    port = 3389

    print(f"[*] Connecting to {host}:{port}")
    print(f"[*] Domain: {domain}, User: {username}")
    print()

    # Step 1: TCP connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    print("[+] TCP connected")

    # Step 2: X224 Connection Request (requesting TLS + NLA)
    connReq = buildX224ConnectionRequest(requestedProtocols=0x03)
    sock.sendall(connReq)
    print("[>] Sent X224 Connection Request (TLS+NLA)")

    # Step 3: X224 Connection Confirm
    time.sleep(1)
    resp = sock.recv(8192)
    if not resp:
        print("[-] No response from server")
        sock.close()
        return False

    confirm = parseX224ConnectionConfirm(resp)
    print(f"[<] X224 Connection Confirm: {confirm}")

    selectedProtocol = confirm.get('selectedProtocol', 0)
    if selectedProtocol & 0x02:
        print("[+] Server selected CredSSP/NLA")
    elif selectedProtocol & 0x01:
        print("[!] Server selected TLS only (no NLA required)")
    else:
        print(f"[-] Unexpected protocol: {selectedProtocol}")
        if confirm.get('negType') == 0x03:
            print("[-] Server sent negotiation failure")
            sock.close()
            return False

    # Step 4: TLS handshake
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tlsSock = ctx.wrap_socket(sock, server_hostname=host)
    print("[+] TLS handshake complete")

    # Get server's TLS public key for pubKeyAuth
    serverCert = tlsSock.getpeercert(binary_form=True)
    from cryptography import x509
    cert = x509.load_der_x509_certificate(serverCert)
    serverPublicKey = cert.public_key().public_bytes(
        encoding=__import__('cryptography.hazmat.primitives.serialization', fromlist=['Encoding']).Encoding.DER,
        format=__import__('cryptography.hazmat.primitives.serialization', fromlist=['PublicFormat']).PublicFormat.SubjectPublicKeyInfo
    )
    print(f"[+] Server TLS public key: {len(serverPublicKey)} bytes")

    # Step 5: CredSSP Step 1 — Send NTLM NEGOTIATE wrapped in SPNEGO + TSRequest
    ntlmNegotiate = buildNTLMNegotiate()
    spnegoInit = buildSpnegoNegTokenInit(ntlmNegotiate)
    tsReq1 = buildTSRequest(version=6, negoTokens=spnegoInit)
    tlsSock.sendall(tsReq1)
    print(f"[>] Sent TSRequest #1 (NTLM NEGOTIATE, {len(tsReq1)} bytes)")

    # Step 6: CredSSP Step 2 — Receive NTLM CHALLENGE
    time.sleep(0.5)
    resp2 = tlsSock.recv(16384)
    if not resp2:
        print("[-] No CredSSP response")
        tlsSock.close()
        return False

    tsResp2 = parseTSRequest(resp2)
    print(f"[<] TSRequest #2: version={tsResp2.get('version')}")

    if 'errorCode' in tsResp2:
        print(f"[-] Server returned error: 0x{tsResp2['errorCode']:08X}")
        tlsSock.close()
        return False

    negoToken2 = tsResp2.get('negoTokens', b'')
    if not negoToken2:
        print("[-] No negoTokens in response")
        tlsSock.close()
        return False

    challenge = parseNTLMChallenge(negoToken2)
    print(f"[+] NTLM CHALLENGE received: challenge={challenge['serverChallenge'].hex()}")
    print(f"    Flags: 0x{challenge['negotiateFlags']:08X}")
    print(f"    TargetInfo: {len(challenge['targetInfo'])} bytes")

    serverVersion = tsResp2.get('version', 2)

    # Extract NetBIOS domain from TargetInfo (used for NTOWFv2 instead of DNS domain)
    netbiosDomain = _extractNetBIOSDomain(challenge['targetInfo'])
    if netbiosDomain:
        print(f"[+] NetBIOS domain from TargetInfo: {netbiosDomain}")
        authDomain = netbiosDomain
    else:
        authDomain = domain
        print(f"[!] No NetBIOS domain in TargetInfo, using: {authDomain}")

    # Step 7: CredSSP Step 3 — Send NTLM AUTHENTICATE + pubKeyAuth
    authMsg, exportedKey = buildNTLMAuthenticate(
        username, authDomain, password,
        challenge['serverChallenge'], challenge['targetInfo'],
        challenge['negotiateFlags']
    )
    print(f"[+] Built AUTHENTICATE message: {len(authMsg)} bytes")
    print(f"[+] Exported session key: {exportedKey.hex()}")

    # Wrap in SPNEGO NegTokenResp
    spnegoResp = buildSpnegoNegTokenResp(authMsg)

    # Compute pubKeyAuth
    nonce = None
    if serverVersion >= 5:
        nonce = os.urandom(32)

    pubKeyAuth = computePubKeyAuth(exportedKey, serverPublicKey, serverVersion, nonce)
    print(f"[+] pubKeyAuth computed: {len(pubKeyAuth)} bytes (version {serverVersion})")

    # Build TSRequest with negoTokens + pubKeyAuth + nonce
    tsReq3 = buildTSRequest(
        version=min(serverVersion, 6),
        negoTokens=spnegoResp,
        pubKeyAuth=pubKeyAuth,
        clientNonce=nonce
    )
    tlsSock.sendall(tsReq3)
    print(f"[>] Sent TSRequest #3 (AUTHENTICATE + pubKeyAuth, {len(tsReq3)} bytes)")

    # Step 8: CredSSP Step 4 — Receive server pubKeyAuth confirmation
    time.sleep(0.5)
    resp4 = tlsSock.recv(16384)
    if not resp4:
        print("[-] No pubKeyAuth confirmation from server")
        tlsSock.close()
        return False

    tsResp4 = parseTSRequest(resp4)
    print(f"[<] TSRequest #4: version={tsResp4.get('version')}")

    if 'errorCode' in tsResp4:
        errCode = tsResp4['errorCode']
        print(f"[-] Server returned error: 0x{errCode:08X}")
        if errCode == 0xC000006D:
            print("    STATUS_LOGON_FAILURE — wrong credentials")
        elif errCode == 0x80090346:
            print("    SEC_E_MUTUAL_AUTH_FAILED — pubKeyAuth mismatch (channel binding)")
        tlsSock.close()
        return False

    if 'pubKeyAuth' in tsResp4:
        print(f"[+] Server pubKeyAuth confirmation: {len(tsResp4['pubKeyAuth'])} bytes")
    else:
        print("[!] No pubKeyAuth in server response (may still be ok)")

    # Step 9: CredSSP Step 5 — Send TSCredentials
    tsCreds = buildTSCredentials(domain, username, password)
    signKey = computeSignKey(exportedKey, clientToServer=True)
    sealKey = computeSealKey(exportedKey, clientToServer=True)
    encryptedCreds = gssWrapEx(signKey, sealKey, 1, tsCreds)

    tsReq5 = buildTSRequest(version=min(serverVersion, 6), authInfo=encryptedCreds)
    tlsSock.sendall(tsReq5)
    print(f"[>] Sent TSRequest #5 (encrypted TSCredentials, {len(tsReq5)} bytes)")

    # Step 10: Check if server accepts (next data should be RDP, not an error)
    time.sleep(1)
    time.sleep(1)
    try:
        resp6 = tlsSock.recv(16384)
    except (socket.timeout, ssl.SSLError):
        resp6 = b''
    if resp6:
        if resp6[0] == 0x30:
            # Another TSRequest — likely an error
            tsResp6 = parseTSRequest(resp6)
            if 'errorCode' in tsResp6:
                print(f"[-] Server error after credentials: 0x{tsResp6['errorCode']:08X}")
                tlsSock.close()
                return False
            print(f"[?] Unexpected TSRequest response: {tsResp6}")
        else:
            print(f"[+] Server sent non-TSRequest data ({len(resp6)} bytes, first byte: 0x{resp6[0]:02x})")
            print("[+] CredSSP authentication likely SUCCEEDED!")
    else:
        print("[+] No error from server — CredSSP authentication likely succeeded")
        print("[+] Connection is now ready for MCS/RDP negotiation")

    print()
    print("=" * 60)
    print("[+] CREDSSP EXCHANGE COMPLETE")
    print("=" * 60)

    tlsSock.close()
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
