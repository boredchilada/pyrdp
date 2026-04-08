#
# This file is part of the PyRDP project.
# Copyright (C) 2024 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
OS and client fingerprinting utilities.

Decodes raw RDP protocol values (clientBuild, keyboardLayout, etc.)
into human-readable strings for honeypot intelligence collection.
"""

# Windows build number → friendly OS version
# Source: https://learn.microsoft.com/en-us/windows/release-health/
WINDOWS_BUILDS = {
    2195: "Windows 2000",
    2600: "Windows XP SP0-SP1",
    3790: "Windows XP x64 / Server 2003",
    6000: "Windows Vista",
    6001: "Windows Vista SP1 / Server 2008",
    6002: "Windows Vista SP2 / Server 2008 SP2",
    7600: "Windows 7 / Server 2008 R2",
    7601: "Windows 7 SP1 / Server 2008 R2 SP1",
    9200: "Windows 8 / Server 2012",
    9600: "Windows 8.1 / Server 2012 R2",
    10240: "Windows 10 1507",
    10586: "Windows 10 1511",
    14393: "Windows 10 1607 / Server 2016",
    15063: "Windows 10 1703",
    16299: "Windows 10 1709",
    17134: "Windows 10 1803",
    17763: "Windows 10 1809 / Server 2019",
    18362: "Windows 10 1903",
    18363: "Windows 10 1909",
    19041: "Windows 10 2004",
    19042: "Windows 10 20H2",
    19043: "Windows 10 21H1",
    19044: "Windows 10 21H2",
    19045: "Windows 10 22H2",
    20348: "Windows Server 2022",
    22000: "Windows 11 21H2",
    22621: "Windows 11 22H2",
    22631: "Windows 11 23H2",
    26100: "Windows 11 24H2 / Server 2025",
}

# Keyboard layout IDs → locale string
# Source: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales
KEYBOARD_LAYOUTS = {
    0x0401: "ar-SA",
    0x0402: "bg-BG",
    0x0403: "ca-ES",
    0x0404: "zh-TW",
    0x0405: "cs-CZ",
    0x0406: "da-DK",
    0x0407: "de-DE",
    0x0408: "el-GR",
    0x0409: "en-US",
    0x040A: "es-ES",
    0x040B: "fi-FI",
    0x040C: "fr-FR",
    0x040D: "he-IL",
    0x040E: "hu-HU",
    0x040F: "is-IS",
    0x0410: "it-IT",
    0x0411: "ja-JP",
    0x0412: "ko-KR",
    0x0413: "nl-NL",
    0x0414: "nb-NO",
    0x0415: "pl-PL",
    0x0416: "pt-BR",
    0x0418: "ro-RO",
    0x0419: "ru-RU",
    0x041A: "hr-HR",
    0x041B: "sk-SK",
    0x041C: "sq-AL",
    0x041D: "sv-SE",
    0x041E: "th-TH",
    0x041F: "tr-TR",
    0x0420: "ur-PK",
    0x0421: "id-ID",
    0x0422: "uk-UA",
    0x0424: "sl-SI",
    0x0425: "et-EE",
    0x0426: "lv-LV",
    0x0427: "lt-LT",
    0x0429: "fa-IR",
    0x042A: "vi-VN",
    0x042B: "hy-AM",
    0x042D: "eu-ES",
    0x0432: "tn-ZA",
    0x0436: "af-ZA",
    0x0437: "ka-GE",
    0x0438: "fo-FO",
    0x0439: "hi-IN",
    0x043E: "ms-MY",
    0x043F: "kk-KZ",
    0x0440: "ky-KG",
    0x0443: "uz-Latn-UZ",
    0x0444: "tt-RU",
    0x0446: "pa-IN",
    0x0449: "ta-IN",
    0x044A: "te-IN",
    0x044B: "kn-IN",
    0x044E: "mr-IN",
    0x0450: "mn-MN",
    0x0456: "gl-ES",
    0x0468: "ha-Latn-NG",
    0x046A: "yo-NG",
    0x0480: "ug-CN",
    0x0804: "zh-CN",
    0x0807: "de-CH",
    0x0809: "en-GB",
    0x080A: "es-MX",
    0x080C: "fr-BE",
    0x0813: "nl-BE",
    0x0816: "pt-PT",
    0x0C04: "zh-HK",
    0x0C09: "en-AU",
    0x0C0A: "es-ES",
    0x0C0C: "fr-CA",
    0x1004: "zh-SG",
    0x1009: "en-CA",
    0x100C: "fr-CH",
    0x1409: "en-NZ",
    0x1809: "en-IE",
    0x1C09: "en-ZA",
    0x2009: "en-JM",
    0x2409: "en-029",  # Caribbean
    0x2809: "en-BZ",
    0x3009: "en-ZW",
    0x3409: "en-PH",
    0x4009: "en-IN",
}


def resolveWindowsBuild(buildNumber: int) -> str:
    """Resolve a Windows build number to a friendly OS version string."""
    if buildNumber in WINDOWS_BUILDS:
        return WINDOWS_BUILDS[buildNumber]

    # Find the closest known build that's <= the given number
    candidates = [b for b in WINDOWS_BUILDS if b <= buildNumber]
    if candidates:
        closest = max(candidates)
        return f"{WINDOWS_BUILDS[closest]} (build {buildNumber})"

    return f"Unknown (build {buildNumber})"


def resolveKeyboardLayout(layoutId: int) -> str:
    """Resolve a keyboard layout ID to a locale string."""
    if layoutId in KEYBOARD_LAYOUTS:
        return KEYBOARD_LAYOUTS[layoutId]
    return f"0x{layoutId:04X}"


def resolveNTLMVersion(versionBytes: bytes) -> str:
    """Decode NTLM VERSION structure (8 bytes) into OS version string.

    Structure: ProductMajorVersion(1) ProductMinorVersion(1)
               ProductBuild(2) Reserved(3) NTLMRevisionCurrent(1)
    """
    if not versionBytes or len(versionBytes) < 8:
        return ""

    major = versionBytes[0]
    minor = versionBytes[1]
    build = int.from_bytes(versionBytes[2:4], 'little')
    revision = versionBytes[7]

    osName = resolveWindowsBuild(build)
    return f"{major}.{minor}.{build} ({osName}, NTLM revision {revision})"
