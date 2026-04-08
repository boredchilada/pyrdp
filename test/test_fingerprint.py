#
# This file is part of the PyRDP project.
# Copyright (C) 2024 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Tests for the OS and client fingerprinting module.
"""

import unittest

from pyrdp.mitm.fingerprint import resolveWindowsBuild, resolveKeyboardLayout, resolveNTLMVersion


class TestResolveWindowsBuild(unittest.TestCase):

    def test_exactMatch(self):
        self.assertEqual(resolveWindowsBuild(22621), "Windows 11 22H2")
        self.assertEqual(resolveWindowsBuild(19045), "Windows 10 22H2")
        self.assertEqual(resolveWindowsBuild(7601), "Windows 7 SP1 / Server 2008 R2 SP1")
        self.assertEqual(resolveWindowsBuild(2600), "Windows XP SP0-SP1")

    def test_server2019(self):
        self.assertEqual(resolveWindowsBuild(17763), "Windows 10 1809 / Server 2019")

    def test_server2022(self):
        self.assertEqual(resolveWindowsBuild(20348), "Windows Server 2022")

    def test_unknownBuild_closestMatch(self):
        # Build slightly above a known one should show closest + actual build
        result = resolveWindowsBuild(22625)
        self.assertIn("Windows 11 22H2", result)
        self.assertIn("22625", result)

    def test_unknownBuild_veryOld(self):
        result = resolveWindowsBuild(1000)
        self.assertIn("Unknown", result)
        self.assertIn("1000", result)

    def test_windows11_24H2(self):
        self.assertEqual(resolveWindowsBuild(26100), "Windows 11 24H2 / Server 2025")


class TestResolveKeyboardLayout(unittest.TestCase):

    def test_commonLayouts(self):
        self.assertEqual(resolveKeyboardLayout(0x0409), "en-US")
        self.assertEqual(resolveKeyboardLayout(0x0809), "en-GB")
        self.assertEqual(resolveKeyboardLayout(0x040C), "fr-FR")
        self.assertEqual(resolveKeyboardLayout(0x0407), "de-DE")
        self.assertEqual(resolveKeyboardLayout(0x0419), "ru-RU")
        self.assertEqual(resolveKeyboardLayout(0x0411), "ja-JP")
        self.assertEqual(resolveKeyboardLayout(0x0412), "ko-KR")
        self.assertEqual(resolveKeyboardLayout(0x0804), "zh-CN")

    def test_unknownLayout(self):
        result = resolveKeyboardLayout(0xFFFF)
        self.assertEqual(result, "0xFFFF")

    def test_zeroLayout(self):
        result = resolveKeyboardLayout(0)
        self.assertEqual(result, "0x0000")


class TestResolveNTLMVersion(unittest.TestCase):

    def test_windows11Build(self):
        # Major=10, Minor=0, Build=22621 (little-endian: 0x5E65), Reserved=0, Revision=15
        versionBytes = bytes([10, 0, 0x65, 0x58, 0, 0, 0, 15])
        result = resolveNTLMVersion(versionBytes)
        self.assertIn("10.0", result)
        self.assertIn("NTLM revision 15", result)

    def test_windows7Build(self):
        # Major=6, Minor=1, Build=7601
        build = 7601
        versionBytes = bytes([6, 1, build & 0xFF, (build >> 8) & 0xFF, 0, 0, 0, 15])
        result = resolveNTLMVersion(versionBytes)
        self.assertIn("6.1", result)
        self.assertIn("Windows 7", result)

    def test_emptyBytes(self):
        self.assertEqual(resolveNTLMVersion(b""), "")
        self.assertEqual(resolveNTLMVersion(None), "")

    def test_shortBytes(self):
        self.assertEqual(resolveNTLMVersion(b"\x00\x00"), "")
