#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from logging import LoggerAdapter
from Crypto.PublicKey.RSA import RsaKey

from pyrdp.core import decodeUTF16LE
from pyrdp.enum import ClientInfoFlags, PlayerPDUType
from pyrdp.layer import SecurityLayer
from pyrdp.mitm.config import MITMConfig
from pyrdp.mitm.state import RDPMITMState
from pyrdp.parser import ClientInfoParser
from pyrdp.pdu import SecurityExchangePDU
from pyrdp.recording import Recorder
from pyrdp.security.crypto import RSA


class SecurityMITM:
    """
    MITM component for the security layer.
    """

    def __init__(self, client: SecurityLayer, server: SecurityLayer, log: LoggerAdapter, config: MITMConfig, state: RDPMITMState, recorder: Recorder):
        """
        :param client: security layer for the client side
        :param server: security layer for the server side
        :param log: logger for this component
        :param config: the MITM configuration
        :param state: the MITM state
        :param recorder: recorder for this connection
        """
        self.client = client
        self.server = server
        self.log = log
        self.state = state
        self.config = config
        self.recorder = recorder

        self.client.createObserver(
            onLicensingDataReceived = self.onClientLicensingData,
            onSecurityExchangeReceived = self.onSecurityExchange,
            onClientInfoReceived=self.onClientInfo,
        )

        self.server.createObserver(
            onLicensingDataReceived = self.onServerLicensingData,
        )

    def onSecurityExchange(self, pdu: SecurityExchangePDU):
        """
        Set the security settings' client random from the security exchange.
        :param pdu: the security exchange
        """
        clientRandom = RSA(self.state.rc4RSAKey).decrypt(pdu.clientRandom[:: -1])[:: -1]
        self.state.securitySettings.setClientRandom(clientRandom)

        self.server.sendSecurityExchange(self.state.securitySettings.encryptClientRandom())

    def onClientInfo(self, data: bytes):
        """
        Log the client connection information and replace the username and password if applicable.
        :param data: the client info data
        """
        pdu = ClientInfoParser().parse(data)

        clientAddress = None

        if pdu.extraInfo:
            clientAddress = decodeUTF16LE(pdu.extraInfo.clientAddress)

        # Strip null bytes for clean display
        cleanUser = pdu.username.strip("\x00") if pdu.username else ""
        cleanPass = pdu.password.strip("\x00") if pdu.password else ""
        cleanDomain = pdu.domain.strip("\x00") if pdu.domain else ""
        cleanAddr = clientAddress.strip("\x00") if clientAddress else ""
        cleanShell = pdu.alternateShell.strip("\x00") if pdu.alternateShell else ""
        cleanWorkDir = pdu.workingDir.strip("\x00") if pdu.workingDir else ""

        self.log.info("Client Info: username=%(username)r password=%(password)r domain=%(domain)r clientAddress=%(clientAddress)r", {
            "username": cleanUser,
            "password": cleanPass,
            "domain": cleanDomain,
            "clientAddress": cleanAddr,
        })

        # Log extra client info for fingerprinting
        if pdu.extraInfo:
            clientDir = decodeUTF16LE(pdu.extraInfo.clientDir).strip("\x00") if pdu.extraInfo.clientDir else ""
            self.log.info("Client extra: dir=%(clientDir)r perfFlags=%(perfFlags)s shell=%(shell)r", {
                "clientDir": clientDir,
                "perfFlags": pdu.extraInfo.performanceFlags,
                "shell": cleanShell,
            })

        self.state.clientInfo = {
            "domain": cleanDomain,
            "username": cleanUser,
            "client_address": cleanAddr,
            "alternate_shell": cleanShell,
            "working_dir": cleanWorkDir,
            "code_page": pdu.codePage,
            "info_flags": pdu.flags,
        }

        # Alert on alternateShell — almost always an attacker command
        if cleanShell:
            self.log.warning("alternateShell set (possible command injection): %(shell)r", {
                "shell": cleanShell,
            })
            self.state.clientInfo["shell_suspicious"] = True

        # Decode performance flags for behavioral fingerprint
        if pdu.extraInfo:
            if pdu.extraInfo.clientDir:
                self.state.clientInfo["client_dir"] = decodeUTF16LE(pdu.extraInfo.clientDir).strip("\x00")
            if pdu.extraInfo.performanceFlags is not None:
                pf = pdu.extraInfo.performanceFlags
                self.state.clientInfo["performance_flags"] = pf
                self.state.clientInfo["performance_flags_decoded"] = {
                    "disable_wallpaper": bool(pf & 0x01),
                    "disable_full_window_drag": bool(pf & 0x02),
                    "disable_menu_animations": bool(pf & 0x04),
                    "disable_theming": bool(pf & 0x08),
                    "disable_cursor_shadow": bool(pf & 0x20),
                    "disable_cursor_settings": bool(pf & 0x40),
                    "enable_font_smoothing": bool(pf & 0x80),
                    "enable_desktop_composition": bool(pf & 0x100),
                }
                # All visual effects disabled = likely scripted tool
                allDisabled = (pf & 0x6F) == 0x6F and not (pf & 0x180)
                if allDisabled:
                    self.state.clientInfo["scripted_connection"] = True
                    self.log.info("Performance flags suggest scripted/automated connection (all visuals disabled)")
            if pdu.extraInfo.clientSessionID is not None:
                self.state.clientInfo["client_session_id"] = pdu.extraInfo.clientSessionID
            if pdu.extraInfo.autoReconnectCookie is not None:
                self.state.clientInfo["auto_reconnect"] = True
                self.log.info("Auto-reconnect cookie present (attacker may be resuming prior session)")
            if pdu.extraInfo.dynamicDSTTimeZoneKeyName:
                tzName = pdu.extraInfo.dynamicDSTTimeZoneKeyName
                if isinstance(tzName, bytes):
                    tzName = tzName.decode("utf-16le", errors="replace")
                self.state.clientInfo["timezone_name"] = tzName.strip("\x00")
            if pdu.extraInfo.dynamicDaylightTimeDisabled is not None:
                self.state.clientInfo["dst_disabled"] = bool(pdu.extraInfo.dynamicDaylightTimeDisabled)
            # Timezone bias for geolocation
            if hasattr(pdu.extraInfo, 'clientTimeZone') and pdu.extraInfo.clientTimeZone:
                tz = pdu.extraInfo.clientTimeZone
                if hasattr(tz, 'bias'):
                    self.state.clientInfo["timezone_bias_minutes"] = tz.bias
                if hasattr(tz, 'standardBias'):
                    self.state.clientInfo["timezone_standard_bias"] = tz.standardBias
                if hasattr(tz, 'daylightBias'):
                    self.state.clientInfo["timezone_daylight_bias"] = tz.daylightBias

        self.state.capturedUsername = cleanUser
        self.state.capturedPassword = cleanPass

        authMethod = "NLA/CredSSP" if self.state.serverRequiresNLA else "TLS"
        self.log.info("[+] Session authenticated (%(method)s): user=%(user)r domain=%(domain)r", {
            "method": authMethod,
            "user": cleanUser,
            "domain": cleanDomain,
        })

        # Fleet event: login_success (credentials captured and forwarded)
        self.log.info("login_success", {
            "event_type": "login_success",
            "src_ip": self.state.clientIp or "",
            "src_port": self.state.clientPort or 0,
            "username": cleanUser,
            "password": cleanPass,
            "password_length": len(cleanPass),
            "rdp": self.state.rdpFingerprint,
            "client_info": self.state.clientInfo,
        })

        self.recorder.record(pdu, PlayerPDUType.CLIENT_INFO)

        # If set, replace the provided username and password to connect the user regardless of
        # the credentials they entered.
        if self.config.replacementUsername is not None:
            pdu.username = self.config.replacementUsername
        if self.config.replacementPassword is not None:
            pdu.password = self.config.replacementPassword

        if self.config.replacementUsername is not None and self.config.replacementPassword is not None:
            pdu.flags |= ClientInfoFlags.INFO_AUTOLOGON

        # Tell the server we don't want compression (unsure of the effectiveness of these flags)
        pdu.flags &= ~ClientInfoFlags.INFO_COMPRESSION
        pdu.flags &= ~ClientInfoFlags.INFO_CompressionTypeMask

        self.log.debug("Sending %(pdu)s", {"pdu": pdu})
        self.server.sendClientInfo(pdu)

    def onServerLicensingData(self, data: bytes):
        """
        Forward licensing data to the client and disable security headers if TLS is in use.
        :param data: the licensing data
        """
        if self.state.useTLS:
            self.client.securityHeaderExpected = False
            self.server.securityHeaderExpected = False

        self.client.sendLicensing(data)

    def onClientLicensingData(self, data: bytes):
        """
        Forward licensing data to the server and disable security headers if TLS is in use.
        :param data: the licensing data
        """
        if self.state.useTLS:
            self.client.securityHeaderExpected = False
            self.server.securityHeaderExpected = False

        self.server.sendLicensing(data)