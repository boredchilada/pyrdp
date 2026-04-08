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
