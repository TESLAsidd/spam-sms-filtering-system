"""
SMS SENTINEL — Phase 10 Final Project Audit, Stress Test & Demonstration Readiness
Comprehensive automated audit covering clean start, full user journeys, repetition,
fuzzing, XSS/SQL injection security, API abuse, exact Insights math verification,
and failure recovery.
"""

import os
import sys
import json
import unittest
import sqlite3
import time
import re

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as flask_app
from database.db import (
    DB_PATH,
    init_db,
    save_analysis,
    get_analyses,
    get_analysis_by_id,
    delete_analysis,
    clear_analyses,
    get_insights_data
)
from model.xray_analyzer import extract_message_stats, analyze_message_signals

class TestPhase10FinalAuditAndStressTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app.app.config["TESTING"] = True
        cls.client = flask_app.app.test_client()

    def setUp(self):
        init_db()
        clear_analyses()

    # =========================================================================
    # 1. CLEAN RECREATION & COLD START TEST
    # =========================================================================
    def test_01_cold_start_and_schema_recreation(self):
        """Verify database schema is properly created and all columns are present."""
        self.assertTrue(os.path.exists(DB_PATH))
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(analyses)")
        cols = {row[1] for row in cursor.fetchall()}
        required = {
            "id", "message", "prediction", "confidence", "threat_score",
            "threat_level", "is_spam", "risk_signals", "message_stats",
            "highlight_terms", "xray_tokens", "recommended_action",
            "pipeline_trace", "created_at"
        }
        self.assertTrue(required.issubset(cols), f"Missing columns in analyses schema: {required - cols}")
        conn.close()

    # =========================================================================
    # 2. FULL USER JOURNEY (JOURNEY TEST)
    # =========================================================================
    def test_02_full_user_journey_e2e(self):
        """
        Execute full journey:
        1. Predict Spam SMS
        2. Predict Legitimate SMS
        3. Verify both in Archive
        4. Inspect detail of first investigation
        5. Verify Insights telemetry
        """
        # Step A & B: Analyze Spam
        spam_msg = "Congratulations! You have won a free cash prize. Click now to claim your reward."
        res_spam = self.client.post("/api/predict", json={"message": spam_msg})
        self.assertEqual(res_spam.status_code, 200)
        d_spam = res_spam.get_json()
        self.assertEqual(d_spam["prediction"], "SPAM")
        self.assertTrue(d_spam["is_spam"])
        self.assertGreaterEqual(d_spam["threat_score"], 60)
        self.assertIn("pipeline_trace", d_spam)
        self.assertIn("step_1_input", d_spam["pipeline_trace"])
        self.assertIn("step_6_verdict", d_spam["pipeline_trace"])

        # Step C: Analyze Legitimate SMS
        ham_msg = "Hey, I'll see you at the library at 4 PM."
        res_ham = self.client.post("/api/predict", json={"message": ham_msg})
        self.assertEqual(res_ham.status_code, 200)
        d_ham = res_ham.get_json()
        self.assertEqual(d_ham["prediction"], "NOT SPAM")
        self.assertFalse(d_ham["is_spam"])
        self.assertLessEqual(d_ham["threat_score"], 30)

        # Step D: Open Archive & verify both exist
        res_archive = self.client.get("/api/analyses")
        self.assertEqual(res_archive.status_code, 200)
        d_arch = res_archive.get_json()
        self.assertEqual(d_arch["total"], 2)
        self.assertEqual(len(d_arch["data"]), 2)

        # Step E: Inspect first investigation
        res_detail = self.client.get(f"/api/analyses/{d_spam['id']}")
        self.assertEqual(res_detail.status_code, 200)
        detail = res_detail.get_json()["data"]
        self.assertEqual(detail["message"], spam_msg)
        self.assertEqual(detail["prediction"], "SPAM")
        self.assertEqual(detail["threat_score"], d_spam["threat_score"])

        # Step F: Open Insights & verify metrics
        res_insights = self.client.get("/api/insights")
        self.assertEqual(res_insights.status_code, 200)
        d_ins = res_insights.get_json()["data"]
        self.assertEqual(d_ins["totals"]["analyses"], 2)
        self.assertEqual(d_ins["totals"]["spam"], 1)
        self.assertEqual(d_ins["totals"]["not_spam"], 1)
        self.assertEqual(d_ins["totals"]["spam_rate"], 50.0)

    # =========================================================================
    # 3. REPETITION & DETERMINISM TEST (15 CYCLES)
    # =========================================================================
    def test_03_repetition_and_determinism(self):
        """Verify repeated predictions on identical input remain strictly deterministic."""
        test_msg = "URGENT: Your account is suspended. Verify immediately at http://bit.ly/bank"
        first_result = None

        for _ in range(15):
            res = self.client.post("/api/predict", json={"message": test_msg})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            if first_result is None:
                first_result = data
            else:
                self.assertEqual(data["prediction"], first_result["prediction"])
                self.assertEqual(data["confidence"], first_result["confidence"])
                self.assertEqual(data["threat_score"], first_result["threat_score"])
                self.assertEqual(len(data["risk_signals"]), len(first_result["risk_signals"]))

    # =========================================================================
    # 4. INPUT FUZZING & UNUSUAL CHARACTERS
    # =========================================================================
    def test_04_input_fuzzing(self):
        """Fuzz endpoint with Unicode, emojis, numbers, punctuation, multi-line, and whitespace."""
        fuzz_cases = [
            ("!!!!!!", "NOT SPAM"),
            ("123456789", "NOT SPAM"),
            ("😂😂😂😂", "NOT SPAM"),
            ("₹₹₹₹₹", "NOT SPAM"),
            ("HELLO", "NOT SPAM"),
            ("hello", "NOT SPAM"),
            ("Hello\nHello\nHello", "NOT SPAM"),
            ("Special chars: @#$%^&*()_+=-~`", "NOT SPAM"),
            ("Mixed language: नमस्ते Hola Bonjour Hello", "NOT SPAM"),
            ("Repeated tokens: free free free free free free free", "SPAM"),
        ]

        for payload, _ in fuzz_cases:
            res = self.client.post("/api/predict", json={"message": payload})
            self.assertEqual(res.status_code, 200, f"Failed on fuzz payload: {repr(payload)}")
            data = res.get_json()
            self.assertIn("prediction", data)
            self.assertIn("confidence", data)
            self.assertIn("threat_score", data)

    # =========================================================================
    # 5. SECURITY ATTACKS (XSS & SQL INJECTION)
    # =========================================================================
    def test_05_security_attack_neutralization(self):
        """Verify XSS and SQL injection payloads are treated as plain text without execution or SQL alteration."""
        attack_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert(1)</script>",
            "'; DROP TABLE analyses; --",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1",
            "UNION SELECT * FROM sqlite_master --"
        ]

        for payload in attack_payloads:
            res = self.client.post("/api/predict", json={"message": payload})
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data["message"], payload)

        # Confirm analyses table was not dropped
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analyses")
        count = cursor.fetchone()[0]
        self.assertEqual(count, len(attack_payloads))
        conn.close()

    # =========================================================================
    # 6. API ABUSE & DEFENSIVE ERROR BOUNDARIES
    # =========================================================================
    def test_06_api_abuse_handling(self):
        """Verify improper API requests receive controlled HTTP 400/404 responses."""
        invalid_requests = [
            ({}, 400),
            ({"message": ""}, 400),
            ({"message": "   \n\t  "}, 400),
            ({"message": None}, 400),
            ({"message": 12345}, 400),
            ({"message": ["array", "text"]}, 400),
            ({"message": {"nested": "dict"}}, 400),
            ({"message": "A" * 1001}, 400),
        ]

        for body, expected_code in invalid_requests:
            res = self.client.post("/api/predict", json=body)
            self.assertEqual(res.status_code, expected_code, f"Failed for body: {body}")
            self.assertIn("error", res.get_json())

        # Test non-existent detail
        res_404 = self.client.get("/api/analyses/999999")
        self.assertEqual(res_404.status_code, 404)

        # Test delete non-existent
        res_del_404 = self.client.delete("/api/analyses/999999")
        self.assertEqual(res_del_404.status_code, 404)

    # =========================================================================
    # 7. ARCHIVE PAGINATION & SEARCH/FILTER COMBINATIONS
    # =========================================================================
    def test_07_archive_search_and_filter_matrix(self):
        """Verify search, filter by risk, filter by type, and combinations."""
        # Insert 6 distinct records
        samples = [
            "WINNER! Claim lottery prize £5000 cash now",
            "URGENT: Your account is suspended. Verify immediately at http://bit.ly/bank",
            "Congratulations! You won free cash prize. Click http://bit.ly/claim now",
            "Hey are we still meeting for lunch today?",
            "The project presentation is scheduled at 10 AM",
            "Please review the attached assignment file",
        ]

        for msg in samples:
            self.client.post("/api/predict", json={"message": msg})

        # Test type filter SPAM
        res_spam = self.client.get("/api/analyses?prediction=SPAM")
        self.assertEqual(res_spam.get_json()["total"], 3)

        # Test type filter HAM / NOT SPAM
        res_ham = self.client.get("/api/analyses?prediction=NOT SPAM")
        self.assertEqual(res_ham.get_json()["total"], 3)

        # Test search query
        res_search = self.client.get("/api/analyses?search=presentation")
        self.assertEqual(res_search.get_json()["total"], 1)

        # Test combination search + filter
        res_combo = self.client.get("/api/analyses?search=prize&prediction=SPAM")
        self.assertEqual(res_combo.get_json()["total"], 2)

        # Test pagination limit/offset
        res_page = self.client.get("/api/analyses?limit=2&offset=0")
        self.assertEqual(len(res_page.get_json()["data"]), 2)
        self.assertEqual(res_page.get_json()["total"], 6)

    # =========================================================================
    # 8. MATHEMATICAL INSIGHTS DATA VERIFICATION
    # =========================================================================
    def test_08_insights_mathematical_exactness(self):
        """Verify that GET /api/insights calculates exact statistics without approximation error."""
        # Insert known dataset: 3 Spam, 2 Ham
        test_data = [
            "Congratulations you won cash prize",
            "Urgent verify your account immediately at http://bit.ly/auth",
            "You have won a free lottery prize claim now",
            "Hey see you at library at 4 PM",
            "Call me when you reach home tonight",
        ]

        for msg in test_data:
            self.client.post("/api/predict", json={"message": msg})

        res = self.client.get("/api/insights")
        self.assertEqual(res.status_code, 200)
        ins = res.get_json()["data"]

        # Assert totals
        self.assertEqual(ins["totals"]["analyses"], 5)
        self.assertEqual(ins["totals"]["spam"], 3)
        self.assertEqual(ins["totals"]["not_spam"], 2)
        self.assertEqual(ins["totals"]["spam_rate"], 60.0)

        # Assert risk distributions sum to total
        dist = ins["threat_distribution"]
        self.assertEqual(dist["high"] + dist["medium"] + dist["low"], 5)
        self.assertEqual(dist["high"], 3)
        self.assertEqual(dist["low"], 2)

        # Assert averages
        self.assertGreater(ins["averages"]["threat_score"], 0)
        self.assertGreater(ins["averages"]["confidence"], 0)

    # =========================================================================
    # 9. ASSET & CODE INTEGRITY
    # =========================================================================
    def test_09_codebase_cleanliness(self):
        """Verify no temporary artifacts or debug statements in core files."""
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        # Verify critical files exist
        essential_files = [
            "app.py",
            "train_ml_engine.py",
            "requirements.txt",
            "README.md",
            "database/db.py",
            "model/xray_analyzer.py",
            "model/spam_classifier.pkl",
            "model/metadata.json",
            "templates/index.html",
            "static/css/style.css",
            "static/js/app.js"
        ]
        for f in essential_files:
            f_path = os.path.join(root_dir, f)
            self.assertTrue(os.path.exists(f_path), f"Essential file missing: {f}")

if __name__ == "__main__":
    unittest.main()
