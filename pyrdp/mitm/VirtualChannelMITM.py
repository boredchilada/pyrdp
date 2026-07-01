#
# This file is part of the PyRDP project.
# Copyright (C) 2019 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

import struct
from logging import LoggerAdapter

from pyrdp.layer import RawLayer
from pyrdp.logging import StatCounter
from pyrdp.logging.StatCounter import STAT
from pyrdp.mitm.state import RDPMITMState
from pyrdp.pdu import PDU


class VirtualChannelMITM:
    """
    Generic MITM component for any virtual channel.
    """

    def __init__(self, client: RawLayer, server: RawLayer, statCounter: StatCounter):
        self.client = client
        self.server = server
        self.statCounter = statCounter

        self.client.createObserver(
            onPDUReceived = self.onClientPDUReceived
        )

        self.server.createObserver(
            onPDUReceived = self.onServerPDUReceived
        )

    def onClientPDUReceived(self, pdu: PDU):
        self.statCounter.increment(STAT.VIRTUAL_CHANNEL_INPUT)
        self.server.sendPDU(pdu)

    def onServerPDUReceived(self, pdu: PDU):
        self.statCounter.increment(STAT.VIRTUAL_CHANNEL, STAT.VIRTUAL_CHANNEL_OUTPUT)
        self.client.sendPDU(pdu)


class DrdynvcMITM(VirtualChannelMITM):
    """
    MITM for the drdynvc (dynamic virtual channel) that extracts RDPEI
    keyboard events from the Microsoft::Windows::RDS::Input channel.
    Forwards all data transparently — read-only interception.
    """

    RDPEI_CHANNEL_NAME = "Microsoft::Windows::RDS::Input"

    # drdynvc command types
    CMD_CREATE = 0x01
    CMD_DATA_FIRST = 0x02
    CMD_DATA = 0x03

    # RDPEI event IDs
    CYCLIC_KEYBOARD_EVENT = 0x0004

    def __init__(self, client: RawLayer, server: RawLayer, statCounter: StatCounter,
                 state: RDPMITMState, log: LoggerAdapter):
        super().__init__(client, server, statCounter)
        self.state = state
        self.log = log
        self._dynamicChannelNames = {}  # channelId → channelName
        self._rdpeiChannelId = None

    def onClientPDUReceived(self, pdu: PDU):
        self._inspectDrdynvc(pdu.payload if pdu.payload else b"", fromClient=True)
        super().onClientPDUReceived(pdu)

    def onServerPDUReceived(self, pdu: PDU):
        self._inspectDrdynvc(pdu.payload if pdu.payload else b"", fromClient=False)
        super().onServerPDUReceived(pdu)

    def _inspectDrdynvc(self, data: bytes, fromClient: bool):
        if len(data) < 2:
            return
        try:
            # Virtual channel PDU wraps drdynvc — skip the 8-byte VC header if present
            # The actual drdynvc data starts after the virtual channel header
            # Try to parse from the raw payload
            self._parseDrdynvc(data, fromClient)
        except Exception:
            pass

    def _parseDrdynvc(self, data: bytes, fromClient: bool):
        header = data[0]
        cbid = header & 0x03
        cmd = (header >> 4) & 0x0F
        offset = 1

        # Read channel ID
        if cbid == 0:
            if offset >= len(data):
                return
            channelId = data[offset]
            offset += 1
        elif cbid == 1:
            if offset + 1 >= len(data):
                return
            channelId = struct.unpack_from('<H', data, offset)[0]
            offset += 2
        elif cbid == 2:
            if offset + 3 >= len(data):
                return
            channelId = struct.unpack_from('<I', data, offset)[0]
            offset += 4
        else:
            return

        if cmd == self.CMD_CREATE and fromClient:
            # Extract channel name (null-terminated ASCII)
            nameBytes = data[offset:]
            nullIdx = nameBytes.find(b'\x00')
            if nullIdx >= 0:
                channelName = nameBytes[:nullIdx].decode('ascii', errors='replace')
                self._dynamicChannelNames[channelId] = channelName
                self.log.debug("drdynvc CREATE: id=%(id)d name=%(name)s",
                               {"id": channelId, "name": channelName})
                if channelName == self.RDPEI_CHANNEL_NAME:
                    self._rdpeiChannelId = channelId
                    self.log.info("RDPEI input channel detected (id=%(id)d)", {"id": channelId})

        elif cmd in (self.CMD_DATA, self.CMD_DATA_FIRST) and fromClient:
            if channelId == self._rdpeiChannelId:
                self._parseRdpeiInput(data[offset:])

    def _parseRdpeiInput(self, data: bytes):
        """Parse RDPEI input PDU to extract keyboard events (MS-RDPEI)."""
        if len(data) < 6:
            return
        try:
            # RDPINPUT_HEADER: eventTime(4) + eventId(2)
            offset = 0
            while offset + 6 <= len(data):
                eventId = struct.unpack_from('<H', data, offset + 4)[0]
                offset += 6

                if eventId == self.CYCLIC_KEYBOARD_EVENT:
                    # CYCLIC_KEYBOARD_EVENT: count(2) then count * {flags(4) + code(2)}
                    if offset + 2 > len(data):
                        break
                    count = struct.unpack_from('<H', data, offset)[0]
                    offset += 2
                    for _ in range(count):
                        if offset + 6 > len(data):
                            break
                        flags = struct.unpack_from('<I', data, offset)[0]
                        scanCode = struct.unpack_from('<H', data, offset + 4)[0]
                        offset += 6
                        isReleased = bool(flags & 0x01)
                        isExtended = bool(flags & 0x02)
                        self._onRdpeiScanCode(scanCode, isReleased, isExtended)
                else:
                    break  # Unknown event, stop parsing
        except Exception:
            pass

    def _onRdpeiScanCode(self, scanCode: int, isReleased: bool, isExtended: bool):
        """Feed RDPEI keyboard event into the existing keystroke capture pipeline."""
        from pyrdp.enum.scancode import getKeyName
        from pyrdp.enum import ScanCode

        keyName = getKeyName(scanCode, isExtended, self.state.shiftPressed, self.state.capsLockOn)
        scanCodeTuple = (scanCode, isExtended)

        # Modifier tracking
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

        # Log keystroke
        if len(keyName) == 1:
            self.log.info("keystroke_capture", {
                "event_type": "keystroke_capture",
                "src_ip": self.state.clientIp or "",
                "src_port": self.state.clientPort or 0,
                "input": keyName,
                "source": "rdpei",
            })
