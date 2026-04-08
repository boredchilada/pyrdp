#
# This file is part of the PyRDP project.
# Copyright (C) 2018-2021 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Contains custom logging handlers for the library.
"""

import binascii
import hashlib
import json
import logging
import os
from datetime import datetime, timezone


class VariableFormatter(logging.Formatter):
    """
    Formatter class that provides custom format variables with default values.
    """

    def __init__(self, fmt: str = None, datefmt: str = None, style: str = "%", defaultVariables: dict = None):
        super().__init__(fmt = fmt, datefmt = datefmt, style = style)
        self.defaultVariables = defaultVariables if defaultVariables is not None else {}

    def format(self, record: logging.LogRecord) -> str:
        for variable, value in self.defaultVariables.items():
            if not hasattr(record, variable):
                setattr(record, variable, value)

        return super().format(record)


class JSONFormatter(logging.Formatter):
    """
    Fleet-standard NDJSON formatter for the connections log (mitm.json).

    When a log record's args dict contains an "event_type" key, emits a
    fleet-compliant JSON line with all 11 mandatory fields from LOGGING_STANDARD.md.
    Records without "event_type" fall back to the legacy PyRDP JSON format for
    backwards compatibility.

    Fleet mandatory fields: @timestamp, event_type, src_ip, src_port, dest_ip,
    dest_port, proto, type, app, session, payload
    """

    # Fields that map to fleet mandatory keys and should not be duplicated
    _FLEET_MANDATORY = {"event_type", "src_ip", "src_port", "dest_ip", "dest_port",
                        "proto", "type", "app", "session", "payload"}

    def __init__(self, baseDict: dict = None):
        """
        :param baseDict: dictionary with base values that should be in every log message.
        """
        super().__init__()
        self.baseDict = baseDict if baseDict is not None else {}

    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.args, dict) and "event_type" in record.args:
            return self._formatFleetEvent(record)
        return self._formatLegacy(record)

    def _formatFleetEvent(self, record: logging.LogRecord) -> str:
        """Format as fleet-standard NDJSON with all 11 mandatory fields."""
        args = record.args

        # Fleet session ID: MD5(IP:date) — correlates same attacker across reconnects
        srcIp = args.get("src_ip", "") or getattr(record, "clientIp", "")
        today = datetime.now(timezone.utc).date()
        fleetSession = hashlib.md5(f"{srcIp}:{today}".encode()).hexdigest()[:16]

        data = {
            "@timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "event_type": args["event_type"],
            "src_ip": srcIp,
            "src_port": args.get("src_port", 0),
            "dest_ip": os.environ.get("DEST_IP", self.baseDict.get("dest_ip", "")),
            "dest_port": os.environ.get("DEST_PORT", self.baseDict.get("dest_port", "3389")),
            "proto": "TCP",
            "type": "pyrdp_rdp",
            "app": "pyrdp",
            "session": fleetSession,
            "session_id": getattr(record, "sessionID", ""),
            "payload": args.get("payload", ""),
        }

        # Add sensor ID from base config
        if "sensor" in self.baseDict:
            data["sensor"] = self.baseDict["sensor"]

        # Merge extra fields (rdp fingerprint, credentials, stats, etc.)
        for k, v in args.items():
            if k not in self._FLEET_MANDATORY:
                data[k] = v

        # Include clientIp if available and not already set as src_ip
        if hasattr(record, "clientIp") and not data.get("src_ip"):
            data["src_ip"] = record.clientIp

        return json.dumps(data, ensure_ascii=False, default=lambda item: str(item))

    def _formatLegacy(self, record: logging.LogRecord) -> str:
        """Legacy PyRDP JSON format for non-fleet log entries."""
        data = self.baseDict.copy()

        data.update({
            "message": record.msg,
            "loggerName": record.name,
            "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "level": record.levelname,
        })

        if hasattr(record, "sessionID"):
            data["sessionID"] = record.sessionID

        if hasattr(record, "clientIp"):
            data["clientIp"] = record.clientIp

        if isinstance(record.args, dict):
            data.update(record.args)

        return json.dumps(data, ensure_ascii=False, default=lambda item: str(item))


class SSLSecretFormatter(logging.Formatter):
    """
    Custom formatter used to log SSL client randoms and master secrets.
    """

    def __init__(self):
        super().__init__()

    def format(self, record: logging.LogRecord) -> str:
        return "CLIENT_RANDOM {} {}".format(binascii.hexlify(record.msg).decode(),
                                            binascii.hexlify(record.args[0]).decode())


class NTLMSSPHashFormatter(logging.Formatter):
    """
    Custom formatter used to log NTLMSSP hashes in hashcat-compatible format.
    Format: user::domain:serverChallenge:NTProofStr:NTResponse
    """

    @staticmethod
    def formatNTLMSSPHash(user: str, domain: str, serverChallenge: bytes, proof: bytes, response: bytes) -> str:
        # Sanitize colons in user/domain — they break the hash format since
        # colon is the field separator. Attackers sometimes type "user:password"
        # in the username field during brute force attempts.
        safeUser = user.replace(":", "_")
        safeDomain = domain.replace(":", "_")
        return f"{safeUser}::{safeDomain}:{serverChallenge.hex()}:{proof.hex()}:{response.hex()}"

    def format(self, record: logging.LogRecord) -> str:
        user = record.msg
        domain, serverChallenge, proof, response = record.args[0 : 4]
        return NTLMSSPHashFormatter.formatNTLMSSPHash(user, domain, serverChallenge, proof, response)
