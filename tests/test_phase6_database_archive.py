"""
SMS SENTINEL - Phase 6 SQLite Database & Archive Automated Test Suite
Verifies database initialization, analyses table persistence, API contracts,
search/filtering/pagination, and data consistency without regressions.
"""

import os
import sys
import json
import unittest
import sqlite3

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as flask_app
from database.db import (
    DB_PATH,
    init_db,
    save_analysis,
    get_analyses,
    get_analysis_by_id,
    delete_analysis,
    clear_analyses
)

class TestPhase6DatabaseAndArchive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app.app.config["TESTING"] = True
        cls.client = flask_app.app.test_client()

    def setUp(self):
        """Ensure clean database state before each test."""
        init_db()
        clear_analyses()

    def test_01_database_initialization(self):
        """Verify SQLite database file exists and analyses table schema is created."""
        self.assertTrue(os.path.exists(DB_PATH), f"Database file missing at {DB_PATH}")
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analyses'")
        table_exists = cursor.fetchone() is not None
        self.assertTrue(table_exists, "analyses table does not exist in SQLite")
        
        # Verify schema columns
        cursor.execute("PRAGMA table_info(analyses)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}
        required_cols = [
            "id", "message", "prediction", "confidence", "threat_score",
            "threat_level", "is_spam", "risk_signals", "message_stats",
            "highlight_terms", "xray_tokens", "recommended_action", "created_at"
        ]
        for col in required_cols:
            self.assertIn(col, columns, f"Column '{col}' missing from analyses table")
        conn.close()

    def test_02_predict_and_persist_spam(self):
        """Verify analyzing a spam message creates an actual SQLite record and returns its real ID."""
        spam_msg = "URGENT: Your bank account is locked. Verify at http://bit.ly/bank-auth immediately."
        res = self.client.post(
            "/api/predict",
            data=json.dumps({"message": spam_msg}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        
        # Must return real SQLite integer ID
        self.assertIn("id", data)
        self.assertIsInstance(data["id"], int)
        self.assertGreater(data["id"], 0)
        self.assertEqual(data["prediction"], "SPAM")
        self.assertTrue(data["is_spam"])
        
        # Verify stored record in SQLite
        stored = get_analysis_by_id(data["id"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored["id"], data["id"])
        self.assertEqual(stored["message"], spam_msg)
        self.assertEqual(stored["prediction"], "SPAM")
        self.assertEqual(stored["threat_score"], data["threat_score"])

    def test_03_predict_and_persist_ham(self):
        """Verify analyzing a legitimate message creates a second record."""
        ham_msg = "Hey Sarah, are we meeting at the campus library at 3 PM today?"
        res = self.client.post(
            "/api/predict",
            data=json.dumps({"message": ham_msg}),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        
        self.assertIn("id", data)
        self.assertEqual(data["prediction"], "NOT SPAM")
        self.assertFalse(data["is_spam"])
        
        stored = get_analysis_by_id(data["id"])
        self.assertIsNotNone(stored)
        self.assertEqual(stored["prediction"], "NOT SPAM")

    def test_04_analyses_endpoint_listing_and_order(self):
        """Verify GET /api/analyses returns newest records first."""
        # Insert 3 messages
        msgs = [
            "Message Alpha: Free bonus reward waiting for you.",
            "Message Beta: Let us grab dinner tonight.",
            "Message Gamma: Call 9876543210 to claim ₹25,000 cash prize."
        ]
        created_ids = []
        for m in msgs:
            r = self.client.post("/api/predict", data=json.dumps({"message": m}), content_type="application/json")
            created_ids.append(r.get_json()["id"])
            
        res = self.client.get("/api/analyses")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        
        self.assertTrue(data["success"])
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["data"]), 3)
        
        # Sorted newest first (highest ID first)
        retrieved_ids = [rec["id"] for rec in data["data"]]
        self.assertEqual(retrieved_ids, sorted(created_ids, reverse=True))

    def test_05_analyses_pagination(self):
        """Verify limit and offset query parameters for pagination."""
        for i in range(15):
            self.client.post(
                "/api/predict",
                data=json.dumps({"message": f"Test message number {i} for pagination verification."}),
                content_type="application/json"
            )
            
        # Request first page (limit=5, offset=0)
        res_p1 = self.client.get("/api/analyses?limit=5&offset=0")
        self.assertEqual(res_p1.status_code, 200)
        d1 = res_p1.get_json()
        self.assertEqual(d1["total"], 15)
        self.assertEqual(len(d1["data"]), 5)
        self.assertEqual(d1["limit"], 5)
        self.assertEqual(d1["offset"], 0)
        self.assertTrue(d1["has_more"])
        
        # Request second page (limit=5, offset=5)
        res_p2 = self.client.get("/api/analyses?limit=5&offset=5")
        d2 = res_p2.get_json()
        self.assertEqual(len(d2["data"]), 5)
        self.assertEqual(d2["offset"], 5)
        self.assertTrue(d2["has_more"])
        
        # Ensure no overlap between page 1 and page 2
        p1_ids = set(r["id"] for r in d1["data"])
        p2_ids = set(r["id"] for r in d2["data"])
        self.assertEqual(len(p1_ids.intersection(p2_ids)), 0)

    def test_06_archive_search(self):
        """Verify search query parameter filters messages directly from SQLite."""
        self.client.post("/api/predict", data=json.dumps({"message": "Win cryptocurrency bitcoin wallet prize"}), content_type="application/json")
        self.client.post("/api/predict", data=json.dumps({"message": "Meeting at the robotics lab tomorrow morning"}), content_type="application/json")
        self.client.post("/api/predict", data=json.dumps({"message": "Exclusive casino jackpot voucher claim now"}), content_type="application/json")
        
        # Search for 'robotics'
        res = self.client.get("/api/analyses?search=robotics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["total"], 1)
        self.assertIn("robotics", data["data"][0]["message"])
        
        # Search for non-existent keyword
        res_none = self.client.get("/api/analyses?search=nonexistentterm123")
        self.assertEqual(res_none.get_json()["total"], 0)
        self.assertEqual(len(res_none.get_json()["data"]), 0)

    def test_07_archive_filters_by_type_and_risk(self):
        """Verify filtering by prediction type (SPAM/HAM) and risk level."""
        self.client.post("/api/predict", data=json.dumps({"message": "Congratulations! You won $50,000 cash. Click http://bit.ly/prize"}), content_type="application/json")
        self.client.post("/api/predict", data=json.dumps({"message": "Hey friend, let's grab coffee at 4"}), content_type="application/json")
        
        # Filter Spam only
        res_spam = self.client.get("/api/analyses?prediction=SPAM")
        d_spam = res_spam.get_json()
        self.assertEqual(d_spam["total"], 1)
        self.assertEqual(d_spam["data"][0]["prediction"], "SPAM")
        
        # Filter Ham only
        res_ham = self.client.get("/api/analyses?prediction=HAM")
        d_ham = res_ham.get_json()
        self.assertEqual(d_ham["total"], 1)
        self.assertEqual(d_ham["data"][0]["prediction"], "NOT SPAM")

    def test_08_single_analysis_retrieval_and_404(self):
        """Verify GET /api/analyses/<id> returns complete detail or 404 for invalid ID."""
        r = self.client.post(
            "/api/predict",
            data=json.dumps({"message": "Your debit card is blocked. Call 9876543210 to unblock."}),
            content_type="application/json"
        )
        rec_id = r.get_json()["id"]
        
        # Valid detail
        res = self.client.get(f"/api/analyses/{rec_id}")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["id"], rec_id)
        self.assertIn("message_stats", data["data"])
        self.assertIn("risk_signals", data["data"])
        self.assertIn("recommended_action", data["data"])
        
        # Invalid detail
        res_404 = self.client.get("/api/analyses/999999")
        self.assertEqual(res_404.status_code, 404)
        self.assertFalse(res_404.get_json()["success"])
        self.assertIn("error", res_404.get_json())

    def test_09_delete_analysis_record(self):
        """Verify DELETE /api/analyses/<id> removes the single record."""
        r = self.client.post(
            "/api/predict",
            data=json.dumps({"message": "Sample message for single deletion test."}),
            content_type="application/json"
        )
        rec_id = r.get_json()["id"]
        
        del_res = self.client.delete(f"/api/analyses/{rec_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.get_json()["success"])
        
        # Verify subsequent GET returns 404
        get_res = self.client.get(f"/api/analyses/{rec_id}")
        self.assertEqual(get_res.status_code, 404)

    def test_10_clear_analyses_endpoint(self):
        """Verify POST /api/analyses/clear removes all records."""
        self.client.post("/api/predict", data=json.dumps({"message": "Message 1"}), content_type="application/json")
        self.client.post("/api/predict", data=json.dumps({"message": "Message 2"}), content_type="application/json")
        
        clear_res = self.client.post("/api/analyses/clear")
        self.assertEqual(clear_res.status_code, 200)
        self.assertTrue(clear_res.get_json()["success"])
        
        res = self.client.get("/api/analyses")
        self.assertEqual(res.get_json()["total"], 0)
        self.assertEqual(len(res.get_json()["data"]), 0)

    def test_11_data_consistency_contract(self):
        """
        Verify mathematical & content equality across:
        /api/predict response == SQLite stored row == /api/analyses/<id> detail.
        """
        msg = "URGENT: Claim ₹50,000 voucher at http://scam.cc/win before midnight!"
        pred_res = self.client.post("/api/predict", data=json.dumps({"message": msg}), content_type="application/json")
        pred_data = pred_res.get_json()
        rec_id = pred_data["id"]
        
        # Fetch from DB directly
        db_row = get_analysis_by_id(rec_id)
        
        # Fetch from GET /api/analyses/<id>
        api_detail = self.client.get(f"/api/analyses/{rec_id}").get_json()["data"]
        
        # Strict consistency assertions
        self.assertEqual(pred_data["prediction"], db_row["prediction"])
        self.assertEqual(pred_data["prediction"], api_detail["prediction"])
        
        self.assertEqual(pred_data["threat_score"], db_row["threat_score"])
        self.assertEqual(pred_data["threat_score"], api_detail["threat_score"])
        
        self.assertEqual(len(pred_data["risk_signals"]), len(db_row["risk_signals"]))
        self.assertEqual(len(pred_data["risk_signals"]), len(api_detail["risk_signals"]))
        
        self.assertEqual(pred_data["message_stats"]["character_count"], api_detail["message_stats"]["character_count"])

    def test_12_failed_requests_do_not_store_records(self):
        """Verify invalid/failed requests (HTTP 400/500) never create fake/incomplete records in SQLite."""
        # Initial count
        init_total = get_analyses()["total"]
        
        # Empty message
        r1 = self.client.post("/api/predict", data=json.dumps({"message": ""}), content_type="application/json")
        self.assertEqual(r1.status_code, 400)
        
        # Whitespace-only
        r2 = self.client.post("/api/predict", data=json.dumps({"message": "    "}), content_type="application/json")
        self.assertEqual(r2.status_code, 400)
        
        # Missing field
        r3 = self.client.post("/api/predict", data=json.dumps({}), content_type="application/json")
        self.assertEqual(r3.status_code, 400)
        
        # Non-string
        r4 = self.client.post("/api/predict", data=json.dumps({"message": 12345}), content_type="application/json")
        self.assertEqual(r4.status_code, 400)
        
        # Over length limit
        r5 = self.client.post("/api/predict", data=json.dumps({"message": "A" * 1200}), content_type="application/json")
        self.assertEqual(r5.status_code, 400)
        
        # Total records must be unchanged
        final_total = get_analyses()["total"]
        self.assertEqual(init_total, final_total, "Invalid requests created unwanted records in database")

if __name__ == "__main__":
    unittest.main()
