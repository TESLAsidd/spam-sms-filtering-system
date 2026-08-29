"""
SMS SENTINEL - Automated Test Suite
Verifies ML predictor, signal engine, SQLite database layer, and Flask REST APIs.
"""

import unittest
import json
import os
import sys

# Ensure root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.predictor import analyze_sms, load_artifacts
from database.db import (
    init_db,
    save_investigation,
    get_investigations,
    get_investigation_by_id,
    delete_investigation,
    clear_investigations,
    get_insights_data
)
from app import app

class TestSMSSentinel(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        load_artifacts()
        cls.client = app.test_client()

    def setUp(self):
        clear_investigations()

    def test_01_ml_and_signal_prediction_spam(self):
        msg = "Congratulations! You have WON ₹50,000 in the lucky draw. Click http://bit.ly/prize immediately to claim your cash reward!"
        res = analyze_sms(msg)
        
        self.assertTrue(res["is_spam"])
        self.assertEqual(res["prediction"], "SPAM")
        self.assertEqual(res["threat_level"], "HIGH RISK")
        self.assertGreaterEqual(res["threat_score"], 70)
        self.assertGreaterEqual(res["confidence"], 80.0)
        
        # Verify detected signals
        sig_keys = [s["key"] for s in res["signals"]]
        self.assertIn("monetary", sig_keys)
        self.assertIn("url_link", sig_keys)
        self.assertIn("urgency", sig_keys)
        self.assertIn("promotional", sig_keys)
        
        # Verify X-Ray tokens
        highlighted = [t for t in res["xray_tokens"] if t["is_signal"]]
        self.assertGreater(len(highlighted), 0)

        # Verify pipeline trace
        self.assertIn("step_3_tfidf", res["pipeline_trace"])
        self.assertIn("step_4_naive_bayes", res["pipeline_trace"])

    def test_02_ml_and_signal_prediction_ham(self):
        msg = "Hey, are you coming to the college library today? Let me know so I can save a seat for you."
        res = analyze_sms(msg)
        
        self.assertFalse(res["is_spam"])
        self.assertEqual(res["prediction"], "NOT SPAM")
        self.assertEqual(res["threat_level"], "LOW RISK")
        self.assertLessEqual(res["threat_score"], 30)
        self.assertGreaterEqual(res["confidence"], 90.0)

    def test_03_database_crud(self):
        msg_spam = "URGENT: Your SBI Bank account has been SUSPENDED. Update KYC at https://sbi-kyc.xyz immediately."
        res_spam = analyze_sms(msg_spam)
        rec_id_1 = save_investigation(res_spam)
        self.assertIsInstance(rec_id_1, int)

        msg_ham = "Hi Mom, reached the hostel safely. Will call after dinner."
        res_ham = analyze_sms(msg_ham)
        rec_id_2 = save_investigation(res_ham)
        self.assertIsInstance(rec_id_2, int)

        # Test retrieval
        records = get_investigations()
        self.assertEqual(len(records), 2)

        # Test single item lookup
        rec1 = get_investigation_by_id(rec_id_1)
        self.assertIsNotNone(rec1)
        self.assertEqual(rec1["threat_level"], "HIGH RISK")
        self.assertEqual(len(rec1["signals"]), len(res_spam["signals"]))

        # Test Insights aggregation
        insights = get_insights_data()
        self.assertTrue(insights["has_data"])
        self.assertEqual(insights["total_analyzed"], 2)
        self.assertEqual(insights["spam_detected"], 1)
        self.assertEqual(insights["legitimate_detected"], 1)
        self.assertEqual(insights["spam_rate"], 50.0)

        # Test deletion
        deleted = delete_investigation(rec_id_1)
        self.assertTrue(deleted)
        remaining = get_investigations()
        self.assertEqual(len(remaining), 1)

    def test_04_api_predict_endpoint(self):
        payload = {"message": "You won $1,000,000! Call 18005550199 to claim."}
        response = self.client.post(
            "/api/predict",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "SPAM")
        self.assertTrue(data["is_spam"])
        self.assertIn("threat_score", data)
        self.assertIn("risk_signals", data)

    def test_05_api_validation_errors(self):
        # Empty message
        response = self.client.post(
            "/api/predict",
            data=json.dumps({"message": "   "}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)
        self.assertIn("cannot be empty", data["error"])

    def test_06_api_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "online")
        self.assertTrue(data["model_loaded"])

if __name__ == "__main__":
    unittest.main()
