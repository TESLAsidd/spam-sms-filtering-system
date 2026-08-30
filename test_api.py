"""
SMS SENTINEL — PHASE 3: FLASK ML API TEST SUITE
Validates endpoints GET / and POST /api/predict, including edge cases and error handling.
"""

import unittest
import json
import os
import sys

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

class TestFlaskMLAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()

    def setUp(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["user_email"] = "test@example.com"
            sess["user_name"] = "Test User"

    def test_01_health_check_endpoint(self):
        """Verify GET / returns 200 and online status."""
        response = self.client.get("/", headers={"Accept": "application/json"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "online")
        self.assertTrue(data["model_loaded"])
        print("\n[PASS] Test 1: GET / (Health Check Online)")

    def test_02_predict_obvious_spam(self):
        """Verify POST /api/predict classifies obvious spam accurately."""
        payload = {
            "message": "Congratulations! You have WON ₹50,000 in the lucky draw. Click http://bit.ly/prize immediately to claim your cash reward!"
        }
        response = self.client.post(
            "/api/predict",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "SPAM")
        self.assertTrue(data["is_spam"])
        self.assertGreaterEqual(data["confidence"], 0.80)
        print(f"[PASS] Test 2: POST /api/predict (Obvious Spam -> {data['prediction']}, Conf: {data['confidence']})")

    def test_03_predict_normal_conversation(self):
        """Verify POST /api/predict classifies legitimate conversation accurately."""
        payload = {
            "message": "Hey, are you coming to the college library today? Let me know so I can save a seat for you."
        }
        response = self.client.post(
            "/api/predict",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "NOT SPAM")
        self.assertFalse(data["is_spam"])
        self.assertGreaterEqual(data["confidence"], 0.80)
        print(f"[PASS] Test 3: POST /api/predict (Normal Message -> {data['prediction']}, Conf: {data['confidence']})")

    def test_04_empty_message_validation(self):
        """Verify POST /api/predict rejects empty or whitespace-only messages."""
        # Empty string
        response1 = self.client.post(
            "/api/predict",
            data=json.dumps({"message": ""}),
            content_type="application/json"
        )
        self.assertEqual(response1.status_code, 400)
        data1 = response1.get_json()
        self.assertIn("cannot be empty", data1["error"])

        # Whitespace-only string
        response2 = self.client.post(
            "/api/predict",
            data=json.dumps({"message": "     "}),
            content_type="application/json"
        )
        self.assertEqual(response2.status_code, 400)
        data2 = response2.get_json()
        self.assertIn("cannot be empty", data2["error"])
        print("[PASS] Test 4: Input Validation (Empty & Whitespace String -> HTTP 400)")

    def test_05_missing_message_field(self):
        """Verify POST /api/predict rejects payloads missing 'message' key."""
        payload = {"text": "Congratulations you won"}
        response = self.client.post(
            "/api/predict",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Missing required field", data["error"])
        print("[PASS] Test 5: Missing 'message' Field -> HTTP 400")

    def test_06_malformed_json_and_headers(self):
        """Verify POST /api/predict rejects non-JSON content-type and bad JSON."""
        # Non-JSON content type
        response1 = self.client.post(
            "/api/predict",
            data="message=Hello",
            content_type="text/plain"
        )
        self.assertEqual(response1.status_code, 400)

        # Malformed JSON
        response2 = self.client.post(
            "/api/predict",
            data="{'message': broken json",
            content_type="application/json"
        )
        self.assertEqual(response2.status_code, 400)
        print("[PASS] Test 6: Malformed JSON & Content-Type Validation -> HTTP 400")

    def test_07_excessively_long_message(self):
        """Verify POST /api/predict rejects strings exceeding 1,000 characters."""
        long_message = "A" * 1050
        response = self.client.post(
            "/api/predict",
            data=json.dumps({"message": long_message}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("exceeds maximum allowed length", data["error"])
        print("[PASS] Test 7: Excessively Long Input (1050 chars -> HTTP 400)")

if __name__ == "__main__":
    unittest.main()
