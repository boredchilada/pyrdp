#
# This file is part of the PyRDP project.
# Copyright (C) 2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO
from typing import Callable, Dict

from pyrdp.core import ber, Uint8, Uint16LE, Uint32LE, Uint64LE
from pyrdp.exceptions import UnknownPDUTypeError, ParsingError
from pyrdp.parser.parser import Parser
from pyrdp.pdu import NTLMSSPChallengePayloadPDU, NTLMSSPTSRequestPDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU, \
    NTLMSSPNegotiatePDU, NTLMSSPPDU
from pyrdp.enum import NTLMSSPMessageType, NTLMSSPChallengeType, NTLMSSPChallengeVersion


class NTLMSSPParser(Parser):
    """
    Parser for NLA/NTLMSSP
    TODO: Add other fields to PDUs if necessary
    TODO: Implement write if necessary
    """

    def __init__(self):
        self.handlers: Dict[int, Callable[[bytes, BytesIO], NTLMSSPPDU]] = {
            1: self.parseNTLMSSPNegotiate,
            2: self.parseNTLMSSPChallenge,
            3: self.parseNTLMSSPAuthenticate
        }

    def findMessage(self, data: bytes) -> int:
        """
        Check if data contains an NTLMSSP message.
        Returns the offset in data of the start of the message or -1 otherwise.
        """
        return data.find(b"NTLMSSP\x00")

    def doParse(self, data: bytes) -> NTLMSSPPDU:
        sigOffset = self.findMessage(data)
        stream    = BytesIO(data[sigOffset:])
        signature = stream.read(8)
        messageType = Uint32LE.unpack(stream)
        return self.handlers[messageType](stream.getvalue(), stream)

    def parseField(self, data: bytes, fields: bytes) -> bytes:
        length = Uint16LE.unpack(fields[0: 2])
        offset = Uint32LE.unpack(fields[4: 8])

        if length != 0:
            return data[offset : offset + length]
        else:
            return b""

    def parseNTLMSSPNegotiate(self, data: bytes, stream: BytesIO) -> NTLMSSPNegotiatePDU:
        negotiateFlags = 0
        domainName = ""
        workstation = ""
        version = b""
        try:
            negotiateFlags = Uint32LE.unpack(stream)
            domainNameFields = stream.read(8)
            workstationFields = stream.read(8)
            if negotiateFlags & 0x02000000:  # NTLMSSP_NEGOTIATE_VERSION
                version = stream.read(8)
            if domainNameFields:
                raw = self.parseField(data, domainNameFields)
                if raw:
                    domainName = raw.decode("utf-16le", errors="replace")
            if workstationFields:
                raw = self.parseField(data, workstationFields)
                if raw:
                    workstation = raw.decode("utf-16le", errors="replace")
        except Exception:
            pass
        return NTLMSSPNegotiatePDU(negotiateFlags, domainName, workstation, version)

    def parseNTLMSSPChallenge(self, data: bytes, stream: BytesIO) -> NTLMSSPChallengePDU:
        workstationLen = Uint16LE.unpack(stream)
        workstationMaxLen = Uint16LE.unpack(stream)
        workstationBufferOffset = Uint32LE.unpack(stream)
        negotiateFlags = Uint32LE.unpack(stream)
        serverChallenge = stream.read(8)
        reserved = Uint64LE.unpack(stream)
        targetInfoLen = Uint16LE.unpack(stream)
        targetInfoMaxLen = Uint16LE.unpack(stream)
        targetInfoBufferOffset = Uint32LE.unpack(stream)
        version = Uint32LE.unpack(stream)
        reserved = stream.read(3)
        revisionCurrent = Uint8.unpack(stream)

        return NTLMSSPChallengePDU(serverChallenge)

    def parseNTLMSSPAuthenticate(self, data: bytes, stream: BytesIO) -> NTLMSSPAuthenticatePDU:
        lmChallengeResponseFields = stream.read(8)
        ntChallengeResponseFields = stream.read(8)
        domainNameFields = stream.read(8)
        userNameFields = stream.read(8)
        workstationFields = stream.read(8)
        encryptedRandomSessionKeyFields = stream.read(8)
        negotiationFlags = stream.read(4)
        version = stream.read(8)
        mic = stream.read(16)

        lmChallengeResponse = self.parseField(data, lmChallengeResponseFields)
        ntChallengeResponse = self.parseField(data, ntChallengeResponseFields)
        domain = self.parseField(data, domainNameFields).decode("utf-16le")
        user = self.parseField(data, userNameFields).decode("utf-16le")
        workstationRaw = self.parseField(data, workstationFields)
        workstation = workstationRaw.decode("utf-16le") if workstationRaw else ""
        encryptedRandomSessionKey = self.parseField(data, encryptedRandomSessionKeyFields)

        # Extract negotiate flags, version, and MIC (parsed but previously discarded)
        negotiateFlags = int.from_bytes(negotiationFlags, 'little') if negotiationFlags else 0
        versionBytes = version if version else b""
        micBytes = mic if mic else b""

        proof = ntChallengeResponse[: 16]
        response = ntChallengeResponse[16 :]

        return NTLMSSPAuthenticatePDU(user, domain, proof, response, workstation,
                                       negotiateFlags, versionBytes, micBytes)

    def parseNTLMSSPTSRequest(self, data: bytes, stream: BytesIO) -> NTLMSSPTSRequestPDU:
        if not ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True):
            raise UnknownPDUTypeError("Invalid BER tag (%d expected)" % ber.Tag.BER_TAG_SEQUENCE)

        length = ber.readLength(stream)
        if length > len(stream.getvalue()):
            raise ParsingError("Invalid size for TSRequest (got %d, %d bytes left)" % (length, len(stream.getvalue())))

        version = None
        negoTokens = None

        # [0] version
        if not ber.readContextualTag(stream, 0, True):
            return NTLMSSPTSRequestPDU(version, negoTokens, data)
        version = ber.readInteger(stream)

        # [1] negoTokens
        if not ber.readContextualTag(stream, 1, True):
            return NTLMSSPTSRequestPDU(version, negoTokens, data)
        ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True)  # SEQUENCE OF NegoDataItem
        ber.readLength(stream)
        ber.readUniversalTag(stream, ber.Tag.BER_TAG_SEQUENCE, True)  # NegoDataItem
        ber.readLength(stream)
        ber.readContextualTag(stream, 0, True)

        negoTokens = BytesIO(ber.readOctetString(stream))  # NegoData
        return NTLMSSPTSRequestPDU(version, negoTokens)

    def parseNTLMSSPChallengePayload(self, data: bytes, stream: BytesIO, workstationLen: int) -> NTLMSSPChallengePayloadPDU:
        workstation = stream.read(workstationLen)
        return NTLMSSPChallengePayloadPDU(workstation)

    def writeNTLMSSPChallenge(self, workstation: str, serverChallenge: bytes,
                              nbDomain: str = None, nbComputer: str = None,
                              dnsDomain: str = None, dnsComputer: str = None,
                              dnsTree: str = None) -> bytes:
        import struct, time
        if nbDomain is None:
            nbDomain = workstation
        if nbComputer is None:
            nbComputer = workstation
        if dnsDomain is None:
            dnsDomain = workstation.lower()
        if dnsComputer is None:
            dnsComputer = f"{workstation.lower()}.{dnsDomain}"
        if dnsTree is None:
            dnsTree = dnsDomain

        targetName = nbDomain.encode('utf-16le')
        targetNameLen = len(targetName)

        avPairs = bytearray()
        for avId, avValue in [
            (0x0002, nbDomain),       # MsvAvNbDomainName
            (0x0001, nbComputer),     # MsvAvNbComputerName
            (0x0004, dnsDomain),      # MsvAvDnsDomainName
            (0x0003, dnsComputer),    # MsvAvDnsComputerName
            (0x0005, dnsTree),        # MsvAvDnsTreeName
        ]:
            encoded = avValue.encode('utf-16le')
            avPairs.extend(struct.pack('<HH', avId, len(encoded)))
            avPairs.extend(encoded)
        # MsvAvTimestamp (0x0007) — Windows FILETIME
        epoch_diff = 116444736000000000
        filetime = int(time.time() * 10000000) + epoch_diff
        avPairs.extend(struct.pack('<HH', 0x0007, 8))
        avPairs.extend(struct.pack('<Q', filetime))
        # MsvAvEOL
        avPairs.extend(struct.pack('<HH', 0x0000, 0))
        pairsLen = len(avPairs)

        fixedLen = 56  # CHALLENGE_MESSAGE fixed header
        targetNameOffset = fixedLen
        targetInfoOffset = fixedLen + targetNameLen

        msg = bytearray(fixedLen + targetNameLen + pairsLen)
        msg[0:8] = b'NTLMSSP\x00'
        struct.pack_into('<I', msg, 8, NTLMSSPMessageType.CHALLENGE_MESSAGE)
        struct.pack_into('<HHI', msg, 12, targetNameLen, targetNameLen, targetNameOffset)
        # Realistic negotiate flags matching rdp-proxy Go code
        flags = (0x00000001 | 0x00000200 | 0x00020000 | 0x00800000 |
                 0x02000000 | 0x20000000 | 0x80000000 | 0x00080000 |
                 0x00008000 | 0x00000010 | 0x40000000)
        struct.pack_into('<I', msg, 20, flags)
        msg[24:32] = serverChallenge
        # Reserved 8 bytes at offset 32 (already zero)
        struct.pack_into('<HHI', msg, 40, pairsLen, pairsLen, targetInfoOffset)
        # Version
        msg[48] = NTLMSSPChallengeVersion.NEG_PROD_MAJOR_VERSION_HIGH
        msg[49] = NTLMSSPChallengeVersion.NEG_PROD_MINOR_VERSION_LOW
        struct.pack_into('<H', msg, 50, NTLMSSPChallengeVersion.NEG_PROD_VERSION_BUILT)
        msg[55] = NTLMSSPChallengeVersion.NEG_NTLM_REVISION_CURRENT

        msg[targetNameOffset:targetNameOffset + targetNameLen] = targetName
        msg[targetInfoOffset:targetInfoOffset + pairsLen] = avPairs

        stream = BytesIO()
        self.writeNTLMSSPTSRequest(stream, NTLMSSPChallengeVersion.CREDSSP_VERSION, bytes(msg))
        return stream.getvalue()

    def writeNTLMSSPTSRequest(self, stream: BytesIO, version: int, negoTokens: bytes):
        """
        Write NTLMSSP TSRequest for NEGOTIATION/CHALLENGE/AUTHENTICATION messages
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685
        """
        negoLen = len(negoTokens)

        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 25))
        stream.write(ber.writeContextualTag(0, 3))
        stream.write(ber.writeInteger(version))  # CredSSP version
        stream.write(ber.writeContextualTag(1, negoLen + 16))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 12))
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(negoLen + 8))
        stream.write(ber.writeContextualTag(0, negoLen + 4))
        stream.write(ber.writeOctetString(negoTokens))

    def writeTSRequestError(self, version: int, errorCode: int) -> bytes:
        """
        Serialize a TSRequest containing only version and errorCode.
        Used to send a clean CredSSP error back to the client after hash capture.
        """
        stream = BytesIO()
        inner = BytesIO()

        # [0] version
        inner.write(ber.writeContextualTag(0, 3))
        inner.write(ber.writeInteger(version))

        # [4] errorCode — encode as unsigned 32-bit big-endian
        errorBytes = errorCode.to_bytes(4, byteorder='big')
        errorTagged = BytesIO()
        errorTagged.write(ber.writeContextualTag(4, 2 + len(errorBytes)))
        errorTagged.write(ber.writeUniversalTag(ber.Tag.BER_TAG_INTEGER, False))
        errorTagged.write(ber.writeLength(len(errorBytes)))
        errorTagged.write(errorBytes)
        inner.write(errorTagged.getvalue())

        innerData = inner.getvalue()
        stream.write(ber.writeUniversalTag(ber.Tag.BER_TAG_SEQUENCE, True))
        stream.write(ber.writeLength(len(innerData)))
        stream.write(innerData)

        return stream.getvalue()

    # writeNTLMSSPChallengePayload removed — AV_PAIRs now built inline in writeNTLMSSPChallenge

