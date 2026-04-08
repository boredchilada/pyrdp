#
# This file is part of the PyRDP project.
# Copyright (C) 2019-2020 GoSecure Inc.
# Licensed under the GPLv3 or later.
#
from logging import LoggerAdapter

from twisted.internet import reactor

from pyrdp.mitm.state import RDPMITMState
from pyrdp.enum import PointerFlag, ScanCode
from pyrdp.enum.scancode import getKeyName
from pyrdp.pdu.pdu import PDU
from pyrdp.layer.layer import Layer
from pyrdp.logging.StatCounter import StatCounter, STAT

# Flush post-login keystroke buffer after this many seconds of inactivity
KEYSTROKE_FLUSH_TIMEOUT = 2.0
# Flush if buffer exceeds this many characters
KEYSTROKE_FLUSH_MAX_LEN = 500


class BasePathMITM:
    """
    Base MITM component for the fast-path and slow-path layers.
    """

    def __init__(self, state: RDPMITMState, client: Layer, server: Layer, statCounter: StatCounter, log: LoggerAdapter):
        self.state = state
        self.client = client
        self.server = server
        self.statCounter = statCounter
        self.log = log
        self._postLoginBuffer = ""
        self._flushDelayed = None

    def onClientPDUReceived(self, pdu: PDU):
        raise NotImplementedError("onClientPDUReceived must be overridden")

    def onServerPDUReceived(self, pdu: PDU):
        raise NotImplementedError("onServerPDUReceived must be overridden")

    def loginAttempt(self):
        if self.state.loggedIn or self.state.inputBuffer == "":
            return

        self.state.credentialsCandidate = self.state.inputBuffer
        self.state.inputBuffer = ""

        self.log.info("Credentials attempt from heuristic: %(credentials_attempt)s", {
            "credentials_attempt": (self.state.credentialsCandidate)
        })

    def onMouse(self, mouseX: int, mouseY: int, pointerFlags: int):
        if pointerFlags & PointerFlag.PTRFLAGS_DOWN != 0:
            percentageX = mouseX / self.state.windowSize[0]
            percentageY = mouseY / self.state.windowSize[1]

            if 0.5 < percentageX < 0.65 and 0.5 < percentageY < 0.65:
                self.loginAttempt()

    def _flushPostLoginBuffer(self, trigger: str = "idle"):
        """Flush accumulated post-login keystrokes as a single fleet event."""
        if not self._postLoginBuffer:
            return
        self.log.info("keystroke_capture", {
            "event_type": "keystroke_capture",
            "src_ip": self.state.clientIp or "",
            "src_port": self.state.clientPort or 0,
            "input": self._postLoginBuffer,
            "trigger": trigger,
            "phase": "post_login",
        })
        self._postLoginBuffer = ""
        self._flushDelayed = None

    def _scheduleFlush(self):
        """Schedule a flush after idle timeout, resetting any existing timer."""
        if self._flushDelayed and self._flushDelayed.active():
            self._flushDelayed.cancel()
        self._flushDelayed = reactor.callLater(KEYSTROKE_FLUSH_TIMEOUT, self._flushPostLoginBuffer, "idle")

    def _appendPostLogin(self, text: str):
        """Append text to post-login buffer and schedule/trigger flush."""
        self._postLoginBuffer += text
        if len(self._postLoginBuffer) >= KEYSTROKE_FLUSH_MAX_LEN:
            self._flushPostLoginBuffer("buffer_full")
        else:
            self._scheduleFlush()

    def onScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """
        Handle scan code for both pre-login (credential heuristic) and post-login (keystroke capture).
        """
        keyName = getKeyName(scanCode, isExtended, self.state.shiftPressed, self.state.capsLockOn)
        scanCodeTuple = (scanCode, isExtended)

        # Modifier key tracking (always active)
        if scanCodeTuple in [ScanCode.LSHIFT, ScanCode.RSHIFT]:
            self.state.shiftPressed = not isReleased
            return
        elif scanCodeTuple == ScanCode.CAPSLOCK and not isReleased:
            self.state.capsLockOn = not self.state.capsLockOn
            return
        elif scanCodeTuple in [ScanCode.LCONTROL, ScanCode.RCONTROL]:
            self.state.ctrlPressed = not isReleased
            return

        if isReleased:
            return

        # Pre-login: credential heuristic (original behavior)
        if not self.state.loggedIn:
            if scanCodeTuple == ScanCode.BACKSPACE:
                self.state.inputBuffer += "<\\b>"
            elif scanCodeTuple == ScanCode.TAB:
                self.state.inputBuffer += "<\\t>"
            elif scanCodeTuple == ScanCode.KEY_A and self.state.ctrlPressed:
                self.state.inputBuffer += "<ctrl-a>"
            elif scanCodeTuple == ScanCode.SPACE:
                self.state.inputBuffer += " "
            elif scanCodeTuple == ScanCode.RETURN:
                self.loginAttempt()
            elif len(keyName) == 1:
                self.state.inputBuffer += keyName
        else:
            # Post-login: buffered keystroke capture for fleet events
            if scanCodeTuple == ScanCode.RETURN:
                self._appendPostLogin("\n")
                self._flushPostLoginBuffer("enter")
            elif scanCodeTuple == ScanCode.BACKSPACE:
                self._appendPostLogin("<\\b>")
            elif scanCodeTuple == ScanCode.TAB:
                self._appendPostLogin("<\\t>")
            elif scanCodeTuple == ScanCode.KEY_A and self.state.ctrlPressed:
                self._appendPostLogin("<ctrl-a>")
            elif scanCodeTuple == ScanCode.SPACE:
                self._appendPostLogin(" ")
            elif len(keyName) == 1:
                self._appendPostLogin(keyName)
