"""
SMS SENTINEL - Phase 7 Real-time SQLite Insights Automated Test Suite
Verifies SQL aggregation, mathematical correctness, known dataset assertions,
threat & classification distributions, risk indicator frequency counts,
activity timelines, and empty/error states without regressions.
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
    get_insights_data,
    get_total_stats,
    get_threat_distribution,
    get_classification_distribution,
    get_activity_data,
    get_risk_indicator_counts,
    get_average_metrics,
    get_recent_activity,
    clear_analyses
)

class TestPhase7InsightsRealtime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        flask_app.app.config["TESTING"] = True
        cls.client = flask_app.app.test_client()

    def setUp(self):
        """Clean database before each test."""
        init_db()
        clear_analyses()
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["user_name"] = "Insights Admin"
            sess["user_email"] = "insights@sentinel.test"

    def tearDown(self):
        """Clean up after test execution."""
        clear_analyses()

    def test_01_empty_database_insights_state(self):
        """Verify GET /api/insights with zero records returns safe empty contracts."""
        res = self.client.get("/api/insights")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data["success"])
        totals = data["totals"]
        self.assertEqual(totals["analyses"], 0)
        self.assertEqual(totals["spam"], 0)
        self.assertEqual(totals["not_spam"], 0)
        self.assertEqual(totals["spam_rate"], 0.0)

        threat_dist = data["threat_distribution"]
        self.assertEqual(threat_dist["low"], 0)
        self.assertEqual(threat_dist["medium"], 0)
        self.assertEqual(threat_dist["high"], 0)

        class_dist = data["classification_distribution"]
        self.assertEqual(class_dist["spam"], 0)
        self.assertEqual(class_dist["not_spam"], 0)

        self.assertEqual(data["activity"], [])
        self.assertEqual(data["risk_indicators"], [])
        self.assertEqual(data["recent"], [])
        self.assertEqual(data["averages"]["confidence"], 0.0)
        self.assertEqual(data["averages"]["threat_score"], 0.0)

    def test_02_known_dataset_mathematical_correctness(self):
        """
        Verify exact mathematical aggregations against known conceptual dataset:
        Record 1: SPAM (threat_score = 90, confidence = 98.0) -> High Risk
        Record 2: NOT SPAM (threat_score = 10, confidence = 99.0) -> Low Risk
        Record 3: SPAM (threat_score = 75, confidence = 95.0) -> High Risk
        """
        save_analysis({
            "message": "Spam test message 1",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_score": 90,
            "threat_level": "HIGH RISK",
            "confidence": 98.0,
            "signals": [{"type": "url", "label": "Suspicious URL"}]
        }, user_id=1)
        save_analysis({
            "message": "Ham test message 2",
            "prediction": "NOT SPAM",
            "is_spam": False,
            "threat_score": 10,
            "threat_level": "LOW RISK",
            "confidence": 99.0,
            "signals": []
        }, user_id=1)
        save_analysis({
            "message": "Spam test message 3",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_score": 75,
            "threat_level": "HIGH RISK",
            "confidence": 95.0,
            "signals": [{"type": "prize", "label": "Prize / Reward"}, {"type": "url", "label": "Suspicious URL"}]
        }, user_id=1)

        res = self.client.get("/api/insights")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        totals = data["totals"]
        self.assertEqual(totals["analyses"], 3)
        self.assertEqual(totals["spam"], 2)
        self.assertEqual(totals["not_spam"], 1)
        self.assertEqual(totals["spam_rate"], 66.7)

        threat_dist = data["threat_distribution"]
        self.assertEqual(threat_dist["low"], 1)     # threat_score <= 33
        self.assertEqual(threat_dist["medium"], 0)  # 34 <= threat_score <= 66
        self.assertEqual(threat_dist["high"], 2)    # threat_score >= 67

        class_dist = data["classification_distribution"]
        self.assertEqual(class_dist["spam"], 2)
        self.assertEqual(class_dist["not_spam"], 1)

        # Expected averages: (90 + 10 + 75) / 3 = 58.333... -> 58.3
        # Expected confidence: (98.0 + 99.0 + 95.0) / 3 = 97.333... -> 97.3
        averages = data["averages"]
        self.assertEqual(averages["threat_score"], 58.3)
        self.assertEqual(averages["confidence"], 97.3)

    def test_03_risk_indicators_frequency_and_ranking(self):
        """Verify frequency aggregation of risk signals stored in SQLite."""
        save_analysis({
            "message": "Msg 1",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_score": 80,
            "signals": [
                {"type": "url", "label": "Suspicious URL"},
                {"type": "urgency", "label": "Urgency"}
            ]
        }, user_id=1)
        save_analysis({
            "message": "Msg 2",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_score": 85,
            "signals": [
                {"type": "url", "label": "Suspicious URL"},
                {"type": "prize", "label": "Prize / Reward"}
            ]
        }, user_id=1)
        save_analysis({
            "message": "Msg 3",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_score": 90,
            "signals": [
                {"type": "url", "label": "Suspicious URL"},
                {"type": "money", "label": "Money"}
            ]
        }, user_id=1)

        res = self.client.get("/api/insights")
        data = res.get_json()
        indicators = data["risk_indicators"]

        # Suspicious URL occurs in all 3 messages -> count 3
        # Urgency, Prize, Money occur in 1 message each -> count 1
        self.assertEqual(len(indicators), 4)
        self.assertEqual(indicators[0]["label"], "Suspicious URL")
        self.assertEqual(indicators[0]["count"], 3)

        other_labels = {ind["label"]: ind["count"] for ind in indicators[1:]}
        self.assertEqual(other_labels.get("Urgency"), 1)
        self.assertEqual(other_labels.get("Prize / Reward"), 1)
        self.assertEqual(other_labels.get("Money"), 1)

    def test_04_activity_timeline_aggregation(self):
        """Verify detection activity grouped by date."""
        self.client.post("/api/predict", data=json.dumps({"message": "Win cash prize today http://win.cc"}), content_type="application/json")
        self.client.post("/api/predict", data=json.dumps({"message": "Hey, see you at dinner at 8 PM"}), content_type="application/json")

        res = self.client.get("/api/insights")
        data = res.get_json()
        activity = data["activity"]

        self.assertGreaterEqual(len(activity), 1)
        today_activity = activity[-1]
        self.assertIn("date", today_activity)
        self.assertEqual(today_activity["total"], 2)
        self.assertEqual(today_activity["spam"], 1)
        self.assertEqual(today_activity["not_spam"], 1)

    def test_05_recent_activity_stream(self):
        """Verify latest analyses stream returns newest 5-10 records."""
        for i in range(8):
            self.client.post(
                "/api/predict",
                data=json.dumps({"message": f"Message record #{i} for recent stream verification."}),
                content_type="application/json"
            )

        res = self.client.get("/api/insights")
        data = res.get_json()
        recent = data["recent"]

        self.assertEqual(len(recent), 8)
        # Newest message should be index 0
        self.assertIn("Message record #7", recent[0]["message"])
        self.assertIn("confidence", recent[0])
        self.assertIn("threat_level", recent[0])
        self.assertIn("prediction", recent[0])

    def test_06_database_functions_isolation(self):
        """Verify standalone modular backend functions in database/db.py."""
        save_analysis({
            "message": "Low threat test",
            "prediction": "NOT SPAM",
            "is_spam": False,
            "threat_score": 15,
            "confidence": 99.5
        })
        save_analysis({
            "message": "Medium threat test",
            "prediction": "NOT SPAM",
            "is_spam": False,
            "threat_score": 45,
            "confidence": 88.0
        })
        save_analysis({
            "message": "High threat test",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_score": 92,
            "confidence": 97.5
        })

        stats = get_total_stats()
        self.assertEqual(stats["analyses"], 3)
        self.assertEqual(stats["spam"], 1)
        self.assertEqual(stats["not_spam"], 2)

        threat_dist = get_threat_distribution()
        self.assertEqual(threat_dist["low"], 1)
        self.assertEqual(threat_dist["medium"], 1)
        self.assertEqual(threat_dist["high"], 1)

        class_dist = get_classification_distribution()
        self.assertEqual(class_dist["spam"], 1)
        self.assertEqual(class_dist["not_spam"], 2)

        avg = get_average_metrics()
        self.assertEqual(avg["threat_score"], round((15 + 45 + 92) / 3, 1))

if __name__ == "__main__":
    unittest.main()
