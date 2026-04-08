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


if __name__ == "__main__":
    unittest.main()
