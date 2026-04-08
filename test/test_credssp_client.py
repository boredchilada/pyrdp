import os
import unittest
from pyrdp.security.credssp import (
    ntowfv2, computeNTLMv2Response, computeSessionBaseKey,
    generateExportedSessionKey, computeSignKey, computeSealKey
)


class TestNTLMComputation(unittest.TestCase):
    """Test NTLM computation using values from MS-NLMP specification."""

    def test_ntowfv2(self):
        password = "Password"
        user = "User"
        domain = "Domain"
        expected = bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f")
        result = ntowfv2(password, user, domain)
        self.assertEqual(result, expected)

    def test_computeNTLMv2Response_structure(self):
        responseKey = bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f")
        serverChallenge = bytes.fromhex("0123456789abcdef")
        clientChallenge = bytes.fromhex("aaaaaaaaaaaaaaaa")
        timestamp = bytes.fromhex("0000000000000000")
        targetInfo = b""

        ntProofStr, ntChallengeResponse = computeNTLMv2Response(
            responseKey, serverChallenge, clientChallenge, timestamp, targetInfo
        )

        self.assertEqual(len(ntProofStr), 16)
        self.assertTrue(ntChallengeResponse.startswith(ntProofStr))
        # temp = 01 01 + 00*6 + timestamp(8) + clientChallenge(8) + 00*4 + targetInfo(0) + 00*4
        expectedTempLen = 2 + 6 + 8 + 8 + 4 + 0 + 4
        self.assertEqual(len(ntChallengeResponse), 16 + expectedTempLen)

    def test_computeSessionBaseKey(self):
        responseKey = bytes.fromhex("0c868a403bfd7a93a3001ef22ef02e3f")
        ntProofStr = os.urandom(16)
        result = computeSessionBaseKey(responseKey, ntProofStr)
        self.assertEqual(len(result), 16)

    def test_generateExportedSessionKey(self):
        keyExchangeKey = os.urandom(16)
        exported, encrypted = generateExportedSessionKey(keyExchangeKey)
        self.assertEqual(len(exported), 16)
        self.assertEqual(len(encrypted), 16)
        # Verify we can decrypt back
        cipher = __import__('Crypto.Cipher.ARC4', fromlist=['ARC4']).new(keyExchangeKey)
        decrypted = cipher.encrypt(encrypted)
        self.assertEqual(decrypted, exported)

    def test_computeSignKey(self):
        key = os.urandom(16)
        signKey = computeSignKey(key, clientToServer=True)
        self.assertEqual(len(signKey), 16)
        # Different direction should give different key
        signKey2 = computeSignKey(key, clientToServer=False)
        self.assertNotEqual(signKey, signKey2)

    def test_computeSealKey(self):
        key = os.urandom(16)
        sealKey = computeSealKey(key, clientToServer=True)
        self.assertEqual(len(sealKey), 16)
        sealKey2 = computeSealKey(key, clientToServer=False)
        self.assertNotEqual(sealKey, sealKey2)


from pyrdp.security.credssp import gssWrapEx, computePubKeyAuth


class TestGSSWrapEx(unittest.TestCase):
    def test_output_format(self):
        signKey = os.urandom(16)
        sealKey = os.urandom(16)
        message = b"test message"

        result = gssWrapEx(signKey, sealKey, 0, message)

        # Version(4) + Checksum(8) + SeqNum(4) + EncryptedMessage
        self.assertEqual(result[:4], b'\x01\x00\x00\x00')
        self.assertEqual(len(result), 4 + 8 + 4 + len(message))

    def test_seqnum_encoded(self):
        signKey = os.urandom(16)
        sealKey = os.urandom(16)
        message = b"test"

        result = gssWrapEx(signKey, sealKey, 42, message)
        seqNum = struct.unpack('<I', result[12:16])[0]
        self.assertEqual(seqNum, 42)

    def test_computePubKeyAuth_v2(self):
        exportedKey = os.urandom(16)
        serverPubKey = os.urandom(256)
        result = computePubKeyAuth(exportedKey, serverPubKey, version=2)
        # Version(4) + Checksum(8) + SeqNum(4) + encrypted(serverPubKey=256)
        self.assertEqual(len(result), 4 + 8 + 4 + 256)

    def test_computePubKeyAuth_v5(self):
        exportedKey = os.urandom(16)
        serverPubKey = os.urandom(256)
        nonce = os.urandom(32)
        result = computePubKeyAuth(exportedKey, serverPubKey, version=5, nonce=nonce)
        # Version(4) + Checksum(8) + SeqNum(4) + encrypted(SHA256=32)
        self.assertEqual(len(result), 4 + 8 + 4 + 32)


import struct

from pyrdp.security.credssp import buildSpnegoNegTokenInit, buildSpnegoNegTokenResp


class TestSPNEGO(unittest.TestCase):
    def test_negTokenInit_starts_with_application_tag(self):
        mechToken = b"NTLMSSP\x00" + b"\x01\x00\x00\x00" + b"\x00" * 28  # fake NEGOTIATE
        result = buildSpnegoNegTokenInit(mechToken)
        # APPLICATION [0] CONSTRUCTED = 0x60
        self.assertEqual(result[0], 0x60)

    def test_negTokenInit_contains_spnego_oid(self):
        mechToken = b"NTLMSSP\x00" + b"\x01\x00\x00\x00" + b"\x00" * 28
        result = buildSpnegoNegTokenInit(mechToken)
        # SPNEGO OID 1.3.6.1.5.5.2 = 06 06 2b 06 01 05 05 02
        self.assertIn(b'\x06\x06\x2b\x06\x01\x05\x05\x02', result)

    def test_negTokenInit_contains_ntlmssp_oid(self):
        mechToken = b"NTLMSSP\x00" + b"\x01\x00\x00\x00" + b"\x00" * 28
        result = buildSpnegoNegTokenInit(mechToken)
        # NTLMSSP OID 1.3.6.1.4.1.311.2.2.10 should be present
        ntlmsspOidEncoded = bytes([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a])
        self.assertIn(ntlmsspOidEncoded, result)

    def test_negTokenInit_contains_mechToken(self):
        mechToken = b"NTLMSSP\x00" + b"\x01\x00\x00\x00" + b"\x00" * 28
        result = buildSpnegoNegTokenInit(mechToken)
        self.assertIn(mechToken, result)

    def test_negTokenResp_starts_with_context_1(self):
        responseToken = b"NTLMSSP\x00" + b"\x03\x00\x00\x00" + b"\x00" * 60  # fake AUTH
        result = buildSpnegoNegTokenResp(responseToken)
        # [1] CONSTRUCTED = 0xA1
        self.assertEqual(result[0], 0xA1)

    def test_negTokenResp_contains_token(self):
        responseToken = b"NTLMSSP\x00" + b"\x03\x00\x00\x00" + b"\x00" * 60
        result = buildSpnegoNegTokenResp(responseToken)
        self.assertIn(responseToken, result)


from pyrdp.security.credssp import buildTSRequest, buildTSCredentials


class TestTSRequest(unittest.TestCase):
    def test_buildTSRequest_version_only(self):
        result = buildTSRequest(version=6)
        # Should be a BER SEQUENCE
        self.assertEqual(result[0], 0x30)
        self.assertGreater(len(result), 4)

    def test_buildTSRequest_with_negoTokens(self):
        negoTokens = b"NTLMSSP\x00" + b"\x01\x00\x00\x00" + b"\x00" * 28
        result = buildTSRequest(version=2, negoTokens=negoTokens)
        self.assertEqual(result[0], 0x30)
        # Should contain the NTLMSSP token somewhere inside
        self.assertIn(b"NTLMSSP\x00", result)

    def test_buildTSRequest_with_pubKeyAuth(self):
        pubKeyAuth = os.urandom(64)
        result = buildTSRequest(version=2, pubKeyAuth=pubKeyAuth)
        self.assertEqual(result[0], 0x30)
        self.assertIn(pubKeyAuth, result)

    def test_buildTSRequest_with_clientNonce(self):
        nonce = os.urandom(32)
        result = buildTSRequest(version=5, clientNonce=nonce)
        self.assertEqual(result[0], 0x30)
        self.assertIn(nonce, result)

    def test_buildTSRequest_full(self):
        """Build a TSRequest with negoTokens + pubKeyAuth + clientNonce."""
        negoTokens = b"NTLMSSP\x00" + b"\x03\x00\x00\x00" + b"\x00" * 60
        pubKeyAuth = os.urandom(48)
        nonce = os.urandom(32)
        result = buildTSRequest(version=5, negoTokens=negoTokens, pubKeyAuth=pubKeyAuth, clientNonce=nonce)
        self.assertEqual(result[0], 0x30)
        self.assertIn(b"NTLMSSP\x00", result)
        self.assertIn(pubKeyAuth, result)
        self.assertIn(nonce, result)

    def test_buildTSCredentials(self):
        result = buildTSCredentials("CONTOSO", "admin", "P@ssw0rd")
        self.assertEqual(result[0], 0x30)
        # Should contain UTF-16LE encoded strings
        self.assertIn("CONTOSO".encode('utf-16-le'), result)
        self.assertIn("admin".encode('utf-16-le'), result)
        self.assertIn("P@ssw0rd".encode('utf-16-le'), result)


if __name__ == "__main__":
    unittest.main()
