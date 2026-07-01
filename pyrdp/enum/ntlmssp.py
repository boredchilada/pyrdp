#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from enum import IntEnum

class NTLMSSPMessageType(IntEnum):
    NEGOTIATE_MESSAGE = 1
    CHALLENGE_MESSAGE = 2
    AUTHENTICATE_MESSAGE = 3

class NTLMSSPChallengeType(IntEnum):
    WORKSTATION_BUFFER_OFFSET = 0x38
    
    # http://davenport.sourceforge.net/ntlm.html#theNtlmFlags
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832
    # Flags: (
    # NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_NTLM |
    # NTLMSSP_NEGOTIATE_ALWAYS_SIGN | NTLMSSP_TARGET_TYPE_SERVER | NTLMSSP_NEGOTIATE_LM_KEY |
    # NTLMSSP_NEGOTIATE_TARGET_INFO | r | NTLMSSP_NEGOTIATE_128 |
    # NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_56
    # )
    NEGOTIATE_FLAGS = 0xE28A8215

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS_ID  = 0x0002 # MsvAvNbDomainName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS1_ID = 0x0001 # MsvAvNbComputerName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS2_ID = 0x0004 # MsvAvDnsDomainName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS3_ID = 0x0003 # MsvAvDnsComputerName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS5_ID = 0x0005 # MsvAvDnsTreeName
    NTLMSSP_NTLM_CHALLENGE_AV_PAIRS6_ID = 0x0000 # MsvAvEOL


class NTLMSSPChallengeVersion(IntEnum):
    CREDSSP_VERSION = 0x06

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175
    NEG_PROD_MAJOR_VERSION_HIGH = 0x0A       # Windows 10+
    NEG_PROD_MINOR_VERSION_LOW  = 0x00
    NEG_PROD_VERSION_BUILT      = 0x4A61     # 19041 (Win10 2004)
    NEG_NTLM_REVISION_CURRENT   = 0x0F      # NTLMSSP_REVISION_W2K3


# NTLM Negotiate flag bits (MS-NLMP section 2.2.2.5)
NTLM_FLAG_NEGOTIATE_UNICODE            = 0x00000001
NTLM_FLAG_NEGOTIATE_OEM                = 0x00000002
NTLM_FLAG_REQUEST_TARGET               = 0x00000004
NTLM_FLAG_NEGOTIATE_SIGN               = 0x00000010
NTLM_FLAG_NEGOTIATE_SEAL               = 0x00000020
NTLM_FLAG_NEGOTIATE_DATAGRAM           = 0x00000040
NTLM_FLAG_NEGOTIATE_LM_KEY             = 0x00000080
NTLM_FLAG_NEGOTIATE_NTLM              = 0x00000200
NTLM_FLAG_NEGOTIATE_OEM_DOMAIN        = 0x00001000
NTLM_FLAG_NEGOTIATE_OEM_WORKSTATION   = 0x00002000
NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN       = 0x00008000
NTLM_FLAG_TARGET_TYPE_DOMAIN          = 0x00010000
NTLM_FLAG_TARGET_TYPE_SERVER          = 0x00020000
NTLM_FLAG_NEGOTIATE_EXTENDED_SESSION  = 0x00080000
NTLM_FLAG_NEGOTIATE_TARGET_INFO       = 0x00800000
NTLM_FLAG_NEGOTIATE_VERSION           = 0x02000000
NTLM_FLAG_NEGOTIATE_128               = 0x20000000
NTLM_FLAG_NEGOTIATE_KEY_EXCH          = 0x40000000
NTLM_FLAG_NEGOTIATE_56                = 0x80000000


def decodeNTLMFlags(flags: int) -> dict:
    """Decode NTLM negotiate flags bitmask into a dict of booleans."""
    return {
        "unicode": bool(flags & NTLM_FLAG_NEGOTIATE_UNICODE),
        "oem": bool(flags & NTLM_FLAG_NEGOTIATE_OEM),
        "request_target": bool(flags & NTLM_FLAG_REQUEST_TARGET),
        "sign": bool(flags & NTLM_FLAG_NEGOTIATE_SIGN),
        "seal": bool(flags & NTLM_FLAG_NEGOTIATE_SEAL),
        "datagram": bool(flags & NTLM_FLAG_NEGOTIATE_DATAGRAM),
        "lm_key": bool(flags & NTLM_FLAG_NEGOTIATE_LM_KEY),
        "ntlm": bool(flags & NTLM_FLAG_NEGOTIATE_NTLM),
        "always_sign": bool(flags & NTLM_FLAG_NEGOTIATE_ALWAYS_SIGN),
        "target_type_domain": bool(flags & NTLM_FLAG_TARGET_TYPE_DOMAIN),
        "target_type_server": bool(flags & NTLM_FLAG_TARGET_TYPE_SERVER),
        "extended_session": bool(flags & NTLM_FLAG_NEGOTIATE_EXTENDED_SESSION),
        "target_info": bool(flags & NTLM_FLAG_NEGOTIATE_TARGET_INFO),
        "version": bool(flags & NTLM_FLAG_NEGOTIATE_VERSION),
        "128bit": bool(flags & NTLM_FLAG_NEGOTIATE_128),
        "key_exch": bool(flags & NTLM_FLAG_NEGOTIATE_KEY_EXCH),
        "56bit": bool(flags & NTLM_FLAG_NEGOTIATE_56),
    }
