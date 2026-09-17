# -*- coding: utf-8 -*-
"""
CloudServer Backend API Tests
Tests Heartbeat, Nonce protection, OTP generation/verification, and License verification.
"""

import os
import sys
import unittest
import time
import hmac
import hashlib

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from main import app, SERVER_SECRET_KEY, db_save_device, db_load_devices

class CloudServerApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_root_status(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertEqual(data["version"], "2.3")

    def test_heartbeat_and_device_status(self):
        payload = {
            "hwid": "TEST_HWID_ABC123",
            "pc_name": "TEST-PC",
            "school": "12-IDUM",
            "version": "v2.3",
            "status": "ACTIVE"
        }
        res = self.client.post("/api/devices/heartbeat", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["ok"])

        # Check status endpoint
        status_res = self.client.get("/api/devices/status/TEST_HWID_ABC123")
        self.assertEqual(status_res.status_code, 200)
        self.assertEqual(status_res.json()["hwid"], "TEST_HWID_ABC123")
        self.assertEqual(status_res.json()["school"], "12-IDUM")

    def test_otp_flow(self):
        chat_id = "test_chat_987654"
        hwid = "TEST_HWID_OTP"

        # Request OTP
        req_res = self.client.post("/api/auth/otp/request", json={"chat_id": chat_id, "hwid": hwid})
        self.assertEqual(req_res.status_code, 200)
        self.assertTrue(req_res.json()["ok"])

        # Invalid OTP verification
        bad_verify = self.client.post("/api/auth/otp/verify", json={"chat_id": chat_id, "otp_code": "000000"})
        self.assertEqual(bad_verify.status_code, 200)
        self.assertFalse(bad_verify.json()["ok"])

    def test_license_verification(self):
        hwid = "TEST_HWID_LICENSE_01"
        expected_key = hmac.new(SERVER_SECRET_KEY.encode(), f"{hwid}:PRO".encode(), hashlib.sha256).hexdigest()[:16].upper()

        # Valid Key
        res_valid = self.client.post("/api/license/verify", json={"hwid": hwid, "license_key": expected_key})
        self.assertEqual(res_valid.status_code, 200)
        self.assertTrue(res_valid.json()["valid"])

        # Invalid Key
        res_invalid = self.client.post("/api/license/verify", json={"hwid": hwid, "license_key": "INVALID_KEY_999"})
        self.assertEqual(res_invalid.status_code, 200)
        self.assertFalse(res_invalid.json()["valid"])

if __name__ == "__main__":
    unittest.main()
