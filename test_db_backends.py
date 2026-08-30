"""
SMS SENTINEL — Database Backends & Contract Test Suite
Validates database operations, multi-user isolation, JSON serialization,
query filtering, pagination, and insights aggregation across backends.
"""

import os
import unittest
import uuid

# Ensure local testing runs with SQLite backend
os.environ["DATABASE_TYPE"] = "sqlite"

from database import db, sqlite_backend, supabase_backend


class TestDatabaseBackends(unittest.TestCase):

    def setUp(self):
        """Prepare fresh test credentials for user isolation testing."""
        self.user_a_uid = uuid.uuid4().hex[:8]
        self.user_a_email = f"user_a_{self.user_a_uid}@test.local"
        self.user_b_uid = uuid.uuid4().hex[:8]
        self.user_b_email = f"user_b_{self.user_b_uid}@test.local"

    def test_01_engine_detection(self):
        """Verify engine detection logic."""
        self.assertEqual(db.get_active_database_type(), "sqlite")

        # Test config check
        self.assertFalse(supabase_backend.is_supabase_configured())

    def test_02_user_crud_and_isolation(self):
        """Verify user creation, lookup, and password protection."""
        user_a_id = db.create_user("User Alpha", self.user_a_email, "hash_alpha_123")
        self.assertIsInstance(user_a_id, int)
        self.assertGreater(user_a_id, 0)

        # Lookup by email
        user_a = db.get_user_by_email(self.user_a_email)
        self.assertIsNotNone(user_a)
        self.assertEqual(user_a["id"], user_a_id)
        self.assertEqual(user_a["name"], "User Alpha")
        self.assertEqual(user_a["email"], self.user_a_email)
        self.assertEqual(user_a["password_hash"], "hash_alpha_123")

        # Lookup by ID (password_hash omitted)
        user_a_by_id = db.get_user_by_id(user_a_id)
        self.assertIsNotNone(user_a_by_id)
        self.assertEqual(user_a_by_id["id"], user_a_id)
        self.assertNotIn("password_hash", user_a_by_id)

    def test_03_oauth_identity_linking(self):
        """Verify OAuth identity linking and resolution."""
        user_id = db.create_user("OAuth Tester", f"oauth_{self.user_a_uid}@test.local", "")
        
        # Link GitHub identity
        ident_id = db.link_oauth_identity(user_id, "github", f"gh_{self.user_a_uid}", "gh@test.local")
        self.assertGreater(ident_id, 0)

        # Lookup by OAuth identity
        matched = db.get_user_by_oauth_identity("github", f"gh_{self.user_a_uid}")
        self.assertIsNotNone(matched)
        self.assertEqual(matched["id"], user_id)
        self.assertEqual(matched["provider"], "github")

        # Retrieve user identities
        identities = db.get_user_identities(user_id)
        self.assertEqual(len(identities), 1)
        self.assertEqual(identities[0]["provider"], "github")

    def test_04_analyses_storage_and_multi_user_isolation(self):
        """Verify analyses CRUD and strict user data isolation."""
        user_a_id = db.create_user("User A", self.user_a_email, "hash_a")
        user_b_id = db.create_user("User B", self.user_b_email, "hash_b")

        # User A saves 2 analyses (1 Spam, 1 Ham)
        spam_result_a = {
            "message": "URGENT: Verify your account now at http://fake-bank.xyz",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_level": "HIGH RISK",
            "threat_score": 92,
            "confidence": 99.8,
            "risk_signals": [{"type": "urgency", "label": "Urgent Action Required"}],
            "message_stats": {"char_count": 55, "word_count": 8},
            "highlight_terms": ["URGENT", "Verify"],
            "xray_tokens": [{"token": "URGENT", "weight": 0.85}],
            "recommended_action": {"action": "BLOCK", "guidance": "Do not click link."},
            "pipeline_trace": {"model": "LinearSVC", "calibrated": True}
        }
        rec_a1 = db.save_analysis(spam_result_a, user_id=user_a_id)

        ham_result_a = {
            "message": "Hey team, the project status meeting is at 2 PM.",
            "prediction": "NOT SPAM",
            "is_spam": False,
            "threat_level": "LOW RISK",
            "threat_score": 5,
            "confidence": 99.5,
            "risk_signals": [],
            "message_stats": {"char_count": 48, "word_count": 9},
            "highlight_terms": [],
            "xray_tokens": [],
            "recommended_action": {"action": "ALLOW", "guidance": "Standard message."},
            "pipeline_trace": {"model": "LinearSVC", "calibrated": True}
        }
        rec_a2 = db.save_analysis(ham_result_a, user_id=user_a_id)

        # User B saves 1 analysis (Spam)
        spam_result_b = {
            "message": "You won $10,000 lottery! Call 555-0199 to claim.",
            "prediction": "SPAM",
            "is_spam": True,
            "threat_level": "HIGH RISK",
            "threat_score": 88,
            "confidence": 99.9,
            "risk_signals": [{"type": "financial", "label": "Lottery Scam"}],
            "message_stats": {"char_count": 49, "word_count": 8},
            "highlight_terms": ["lottery"],
            "xray_tokens": [],
            "recommended_action": {"action": "BLOCK"},
            "pipeline_trace": {}
        }
        rec_b1 = db.save_analysis(spam_result_b, user_id=user_b_id)

        # Verify User A's Archive contains exactly 2 records
        analyses_a = db.get_analyses(user_id=user_a_id)
        self.assertEqual(analyses_a["total"], 2)
        self.assertEqual(len(analyses_a["records"]), 2)

        # Verify User B's Archive contains exactly 1 record
        analyses_b = db.get_analyses(user_id=user_b_id)
        self.assertEqual(analyses_b["total"], 1)
        self.assertEqual(len(analyses_b["records"]), 1)
        self.assertEqual(analyses_b["records"][0]["id"], rec_b1)

        # Verify IDOR Protection: User A cannot read User B's analysis
        idor_check = db.get_analysis_by_id(rec_b1, user_id=user_a_id)
        self.assertIsNone(idor_check, "IDOR check failed: User A was able to read User B's record!")

        # Verify User B can read User B's analysis
        valid_check = db.get_analysis_by_id(rec_b1, user_id=user_b_id)
        self.assertIsNotNone(valid_check)
        self.assertEqual(valid_check["id"], rec_b1)

        # Verify Insights Isolation
        insights_a = db.get_insights_data(user_id=user_a_id)
        self.assertEqual(insights_a["totals"]["analyses"], 2)
        self.assertEqual(insights_a["totals"]["spam"], 1)
        self.assertEqual(insights_a["totals"]["not_spam"], 1)
        self.assertEqual(insights_a["totals"]["spam_rate"], 50.0)

        insights_b = db.get_insights_data(user_id=user_b_id)
        self.assertEqual(insights_b["totals"]["analyses"], 1)
        self.assertEqual(insights_b["totals"]["spam"], 1)
        self.assertEqual(insights_b["totals"]["not_spam"], 0)
        self.assertEqual(insights_b["totals"]["spam_rate"], 100.0)

        # Test Search & Filter
        search_res = db.get_analyses(search="meeting", user_id=user_a_id)
        self.assertEqual(search_res["total"], 1)
        self.assertEqual(search_res["records"][0]["id"], rec_a2)

        filter_spam = db.get_analyses(prediction="SPAM", user_id=user_a_id)
        self.assertEqual(filter_spam["total"], 1)
        self.assertEqual(filter_spam["records"][0]["id"], rec_a1)

        # Test Delete with Isolation
        delete_fail = db.delete_analysis(rec_b1, user_id=user_a_id)
        self.assertFalse(delete_fail, "User A should not be able to delete User B's record!")

        delete_success = db.delete_analysis(rec_a1, user_id=user_a_id)
        self.assertTrue(delete_success)
        self.assertEqual(db.get_analyses(user_id=user_a_id)["total"], 1)


if __name__ == "__main__":
    unittest.main()
