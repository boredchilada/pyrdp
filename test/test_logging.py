#
# This file is part of the PyRDP project.
# Copyright (C) 2024 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
Tests for the structured JSON logging formatter.
Validates that structured events contain all required fields and that
legacy log records are formatted correctly.
"""

import json
import logging
import os
import unittest


class TestJSONFormatter(unittest.TestCase):
    """Test the JSONFormatter for structured and legacy output."""

    def setUp(self):
        from pyrdp.logging.formatters import JSONFormatter
        self.formatter = JSONFormatter(baseDict={"sensor": "TestSensor"})

    def _makeRecord(self, msg, args=None, sessionID=None, clientIp=None):
        record = logging.LogRecord(
            name="pyrdp.test", level=logging.INFO, pathname="", lineno=0,
            msg=msg, args=args, exc_info=None
        )
        if sessionID:
            record.sessionID = sessionID
        if clientIp:
            record.clientIp = clientIp
        return record

    def test_structuredEvent_hasRequiredFields(self):
        """Structured events must contain all required NDJSON fields."""
        record = self._makeRecord("connection_open", {
            "event_type": "connection_open",
            "src_ip": "192.168.1.100",
            "src_port": 49152,
        }, sessionID="test_session_123", clientIp="192.168.1.100")

        output = self.formatter.format(record)
        data = json.loads(output)

        requiredFields = [
            "@timestamp", "event_type", "src_ip", "src_port",
            "dest_ip", "dest_port", "proto", "type", "app",
            "session", "payload"
        ]
        for field in requiredFields:
            self.assertIn(field, data, f"Missing required field: {field}")

    def test_structuredEvent_correctValues(self):
        """Structured event field values must match input."""
        record = self._makeRecord("connection_open", {
            "event_type": "connection_open",
            "src_ip": "10.0.0.5",
            "src_port": 12345,
        }, sessionID="my_session")

        data = json.loads(self.formatter.format(record))

        self.assertEqual(data["event_type"], "connection_open")
        self.assertEqual(data["src_ip"], "10.0.0.5")
        self.assertEqual(data["src_port"], 12345)
        self.assertEqual(data["proto"], "TCP")
        self.assertEqual(data["type"], "pyrdp_rdp")
        self.assertEqual(data["app"], "pyrdp")
        self.assertEqual(data["sensor"], "TestSensor")

    def test_structuredEvent_timestampFormat(self):
        """Timestamp must be ISO 8601 UTC with Z suffix and millisecond precision."""
        record = self._makeRecord("test", {
            "event_type": "connection_open",
            "src_ip": "1.2.3.4",
        })
        data = json.loads(self.formatter.format(record))

        ts = data["@timestamp"]
        self.assertTrue(ts.endswith("Z"), f"Timestamp must end with Z: {ts}")
        # Format: 2026-04-08T21:51:09.645Z (23 chars)
        self.assertEqual(len(ts), 24, f"Unexpected timestamp length: {ts}")

    def test_structuredEvent_extraFieldsMerged(self):
        """Extra fields in args dict should be included in output."""
        record = self._makeRecord("login_success", {
            "event_type": "login_success",
            "src_ip": "1.2.3.4",
            "username": "admin",
            "rdp": {"client_build": 22621, "os_version": "Windows 11 22H2"},
        })
        data = json.loads(self.formatter.format(record))

        self.assertEqual(data["username"], "admin")
        self.assertEqual(data["rdp"]["client_build"], 22621)
        self.assertEqual(data["rdp"]["os_version"], "Windows 11 22H2")

    def test_structuredEvent_sessionCorrelation(self):
        """Same src_ip on same day should produce same session hash."""
        record1 = self._makeRecord("e1", {
            "event_type": "connection_open", "src_ip": "10.0.0.1",
        })
        record2 = self._makeRecord("e2", {
            "event_type": "connection_close", "src_ip": "10.0.0.1",
        })

        data1 = json.loads(self.formatter.format(record1))
        data2 = json.loads(self.formatter.format(record2))

        self.assertEqual(data1["session"], data2["session"])
        self.assertEqual(len(data1["session"]), 16)

    def test_structuredEvent_differentIpDifferentSession(self):
        """Different src_ip should produce different session hash."""
        record1 = self._makeRecord("e1", {
            "event_type": "connection_open", "src_ip": "10.0.0.1",
        })
        record2 = self._makeRecord("e2", {
            "event_type": "connection_open", "src_ip": "10.0.0.2",
        })

        data1 = json.loads(self.formatter.format(record1))
        data2 = json.loads(self.formatter.format(record2))

        self.assertNotEqual(data1["session"], data2["session"])

    def test_structuredEvent_sessionIdPreserved(self):
        """PyRDP internal session ID should be in session_id field."""
        record = self._makeRecord("test", {
            "event_type": "connection_open", "src_ip": "1.2.3.4",
        }, sessionID="quirky_name_1234567")

        data = json.loads(self.formatter.format(record))
        self.assertEqual(data["session_id"], "quirky_name_1234567")

    def test_legacyFormat_noEventType(self):
        """Records without event_type should use legacy format."""
        record = self._makeRecord("Server connected", sessionID="test_123")

        data = json.loads(self.formatter.format(record))

        self.assertIn("message", data)
        self.assertIn("timestamp", data)
        self.assertIn("level", data)
        self.assertNotIn("@timestamp", data)
        self.assertNotIn("event_type", data)

    def test_legacyFormat_argsIncluded(self):
        """Legacy format should include args dict values."""
        record = logging.LogRecord(
            name="pyrdp.test", level=logging.INFO, pathname="", lineno=0,
            msg="Client from %(ip)s", args=None, exc_info=None
        )
        record.sessionID = "s1"
        # Attach args after construction to avoid LogRecord formatting
        record.args = {"ip": "1.2.3.4"}

        data = json.loads(self.formatter.format(record))
        self.assertEqual(data["ip"], "1.2.3.4")
        self.assertEqual(data["sessionID"], "s1")

    def test_legacyFormat_nonDictArgs(self):
        """Legacy format should handle non-dict args gracefully."""
        record = self._makeRecord("Port %d", None, sessionID="s1")

        output = self.formatter.format(record)
        data = json.loads(output)
        self.assertIn("message", data)

    def test_envOverrides(self):
        """DEST_IP and DEST_PORT env vars should override defaults."""
        os.environ["DEST_IP"] = "203.0.113.50"
        os.environ["DEST_PORT"] = "13389"
        try:
            record = self._makeRecord("test", {
                "event_type": "connection_open", "src_ip": "1.2.3.4",
            })
            data = json.loads(self.formatter.format(record))
            self.assertEqual(data["dest_ip"], "203.0.113.50")
            self.assertEqual(data["dest_port"], "13389")
        finally:
            del os.environ["DEST_IP"]
            del os.environ["DEST_PORT"]


class TestJSONFormatterEventTypes(unittest.TestCase):
    """Test that all known event types produce valid output."""

    def setUp(self):
        from pyrdp.logging.formatters import JSONFormatter
        self.formatter = JSONFormatter()

    def _formatEvent(self, eventType, **extra):
        record = logging.LogRecord(
            name="pyrdp.test", level=logging.INFO, pathname="", lineno=0,
            msg=eventType, args={"event_type": eventType, "src_ip": "1.2.3.4", "src_port": 1234, **extra},
            exc_info=None
        )
        return json.loads(self.formatter.format(record))

    def test_connectionOpen(self):
        data = self._formatEvent("connection_open")
        self.assertEqual(data["event_type"], "connection_open")

    def test_loginSuccess(self):
        data = self._formatEvent("login_success", username="admin", password="pass123", password_length=7)
        self.assertEqual(data["username"], "admin")
        self.assertEqual(data["password_length"], 7)

    def test_keystrokeCapture(self):
        data = self._formatEvent("keystroke_capture", input="whoami\n", trigger="enter", phase="post_login")
        self.assertEqual(data["input"], "whoami\n")
        self.assertEqual(data["phase"], "post_login")

    def test_exploitAttempt(self):
        data = self._formatEvent("exploit_attempt", attack_patterns={"bluekeep_cve_2019_0708": True})
        self.assertTrue(data["attack_patterns"]["bluekeep_cve_2019_0708"])

    def test_connectionClose(self):
        data = self._formatEvent(
            "connection_close",
            rdp={"client_build": 22621}, stats={"connectionTime": 30.5})
        self.assertEqual(data["rdp"]["client_build"], 22621)
        self.assertEqual(data["stats"]["connectionTime"], 30.5)

    def test_fileWrite(self):
        data = self._formatEvent("file_write", file_path="\\Users\\admin\\malware.exe", write_length=4096)
        self.assertEqual(data["file_path"], "\\Users\\admin\\malware.exe")

    def test_fileDelete(self):
        data = self._formatEvent("file_delete", file_path="\\Windows\\Temp\\evidence.log")
        self.assertEqual(data["event_type"], "file_delete")

    def test_fileRename(self):
        data = self._formatEvent("file_rename", file_path="\\old.txt", new_name="\\new.txt")
        self.assertEqual(data["new_name"], "\\new.txt")
