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

from Crypto.Cipher import ARC4


def _md4(data: bytes) -> bytes:
    """Compute MD4 hash."""
    return hashlib.new('md4', data).digest()


def _hmacMd5(key: bytes, data: bytes) -> bytes:
    """Compute HMAC-MD5."""
    return hmac.new(key, data, hashlib.md5).digest()


def ntowfv2(password: str, user: str, domain: str) -> bytes:
    """
    Compute NTOWFv2 (response key) per MS-NLMP 3.3.2.
    NTOWFv2 = HMAC_MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user) + domain))
    """
    ntHash = _md4(password.encode('utf-16-le'))
    userDomain = (user.upper() + domain).encode('utf-16-le')
    return _hmacMd5(ntHash, userDomain)


def computeNTLMv2Response(responseKey: bytes, serverChallenge: bytes,
                           clientChallenge: bytes, timestamp: bytes,
                           targetInfo: bytes) -> tuple:
    """
    Compute NTLMv2 response per MS-NLMP 3.3.2.
    Returns (NTProofStr, NtChallengeResponse).
    """
    temp = (
        b'\x01\x01'
        + b'\x00' * 6
        + timestamp
        + clientChallenge
        + b'\x00' * 4
        + targetInfo
        + b'\x00' * 4
    )

    ntProofStr = _hmacMd5(responseKey, serverChallenge + temp)
    ntChallengeResponse = ntProofStr + temp

    return ntProofStr, ntChallengeResponse


def computeSessionBaseKey(responseKey: bytes, ntProofStr: bytes) -> bytes:
    """
    Compute SessionBaseKey per MS-NLMP 3.3.2.
    SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    """
    return _hmacMd5(responseKey, ntProofStr)


def generateExportedSessionKey(keyExchangeKey: bytes) -> tuple:
    """
    Generate ExportedSessionKey and EncryptedRandomSessionKey.
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


def gssWrapEx(signKey: bytes, sealKey: bytes, seqNum: int, message: bytes) -> bytes:
    """
    GSS_WrapEx: sign and encrypt a message per MS-NLMP 3.4.4.
    Output: Version(4) + Checksum(8) + SeqNum(4) + EncryptedMessage
    """
    seqNumBytes = struct.pack('<I', seqNum)

    cipher = ARC4.new(sealKey)
    encryptedMessage = cipher.encrypt(message)

    checksum = _hmacMd5(signKey, seqNumBytes + message)[:8]

    cipher2 = ARC4.new(sealKey)
    encryptedChecksum = cipher2.encrypt(checksum)

    version = struct.pack('<I', 1)

    return version + encryptedChecksum + seqNumBytes + encryptedMessage


def computePubKeyAuth(exportedSessionKey: bytes, serverPublicKey: bytes,
                       version: int, nonce: bytes = None) -> bytes:
    """
    Compute pubKeyAuth for CredSSP TSRequest.
    version 2-4: encrypt(serverPublicKey)
    version 5+: encrypt(SHA256("CredSSP Client-To-Server Binding Hash\\0" + nonce + serverPublicKey))
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


def _encodeOid(oid: list) -> bytes:
    """BER-encode an OID value (just the value bytes, no tag/length)."""
    result = bytearray()
    result.append(40 * oid[0] + oid[1])
    for component in oid[2:]:
        if component < 128:
            result.append(component)
        else:
            # Multi-byte encoding
            encoded = []
            while component > 0:
                encoded.append(component & 0x7F)
                component >>= 7
            encoded.reverse()
            for i in range(len(encoded) - 1):
                encoded[i] |= 0x80
            result.extend(encoded)
    return bytes(result)


def _berWriteTagLenVal(tag: int, value: bytes) -> bytes:
    """Write a BER TLV (tag + length + value)."""
    result = bytearray()
    result.append(tag)
    length = len(value)
    if length < 128:
        result.append(length)
    elif length < 256:
        result.append(0x81)
        result.append(length)
    else:
        result.append(0x82)
        result.extend(struct.pack('>H', length))
    result.extend(value)
    return bytes(result)


# OIDs
SPNEGO_OID = [1, 3, 6, 1, 5, 5, 2]
NTLMSSP_OID = [1, 3, 6, 1, 4, 1, 311, 2, 2, 10]


def buildSpnegoNegTokenInit(mechToken: bytes) -> bytes:
    """
    Build SPNEGO NegTokenInit wrapping an NTLMSSP message.
    Used for the first CredSSP message (NTLM NEGOTIATE).

    Structure:
    APPLICATION [0] {
        OID spnego
        [0] NegTokenInit {
            [0] MechTypeList { OID ntlmssp }
            [2] mechToken
        }
    }
    """
    # MechType OID
    oidValue = _encodeOid(NTLMSSP_OID)
    oidTlv = _berWriteTagLenVal(0x06, oidValue)

    # MechTypeList = SEQUENCE OF MechType
    mechTypeList = _berWriteTagLenVal(0x30, oidTlv)

    # [0] mechTypes
    mechTypes = _berWriteTagLenVal(0xA0, mechTypeList)

    # [2] mechToken
    mechTokenOctet = _berWriteTagLenVal(0x04, mechToken)
    mechTokenCtx = _berWriteTagLenVal(0xA2, mechTokenOctet)

    # NegTokenInit = SEQUENCE { mechTypes, mechToken }
    negTokenInit = _berWriteTagLenVal(0x30, mechTypes + mechTokenCtx)

    # [0] CONSTRUCTED wrapping the NegTokenInit
    negTokenInitCtx = _berWriteTagLenVal(0xA0, negTokenInit)

    # SPNEGO OID
    spnegoOidValue = _encodeOid(SPNEGO_OID)
    spnegoOidTlv = _berWriteTagLenVal(0x06, spnegoOidValue)

    # APPLICATION [0] CONSTRUCTED (tag 0x60)
    return _berWriteTagLenVal(0x60, spnegoOidTlv + negTokenInitCtx)


def buildSpnegoNegTokenResp(responseToken: bytes) -> bytes:
    """
    Build SPNEGO NegTokenResp wrapping an NTLMSSP message.
    Used for subsequent CredSSP messages (NTLM AUTHENTICATE).

    Structure:
    [1] NegTokenResp {
        [2] responseToken
    }
    """
    # responseToken as OCTET STRING
    tokenOctet = _berWriteTagLenVal(0x04, responseToken)
    tokenCtx = _berWriteTagLenVal(0xA2, tokenOctet)

    # NegTokenResp = SEQUENCE { responseToken }
    negTokenResp = _berWriteTagLenVal(0x30, tokenCtx)

    # [1] CONSTRUCTED
    return _berWriteTagLenVal(0xA1, negTokenResp)
