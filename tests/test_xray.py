"""
SMS SENTINEL — PHASE 5: MESSAGE X-RAY & INTELLIGENCE TEST SUITE
Validates deterministic pattern extraction, token highlights, statistics,
scoring, and context-aware recommendations.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.xray_analyzer import extract_message_stats, analyze_message_signals

class TestMessageXRayIntelligence(unittest.TestCase):

    def test_01_message_stats_calculation(self):
        """Verify structural statistics are calculated accurately from raw text."""
        sample = "Congratulations! You won $50,000 cash. Click https://claim.xyz or call (800) 555-0199 now!"
        stats = extract_message_stats(sample)
        
        self.assertEqual(stats["character_count"], len(sample))
        self.assertEqual(stats["word_count"], 12)
        self.assertEqual(stats["url_count"], 1)
        self.assertEqual(stats["phone_number_count"], 1)
        self.assertEqual(stats["exclamation_count"], 2)
        self.assertGreater(stats["uppercase_ratio"], 0.0)
        print("\n[PASS] Test 1: Message Stats Calculation (Characters, Words, URLs, Phones, Exclamations)")

    def test_02_prize_spam_analysis(self):
        """Verify prize scam triggers prize, money, url, and urgency categories."""
        sample = "Congratulations! You have won ₹50,000 CASH PRIZE. Click http://claim-now.com immediately."
        res = analyze_message_signals(sample, is_ml_spam=True, ml_confidence=0.999)
        
        # Verify signals
        cat_types = [s["type"] for s in res["risk_signals"]]
        self.assertIn("prize", cat_types)
        self.assertIn("money", cat_types)
        self.assertIn("url", cat_types)
        self.assertIn("urgency", cat_types)
        self.assertIn("cta", cat_types)
        
        # Verify Threat Score
        self.assertGreaterEqual(res["threat_score"], 80)
        
        # Verify Recommendation
        self.assertEqual(res["recommended_action"]["status"], "HIGH_RISK")
        
        # Verify X-Ray Token highlighting
        highlights = [t for t in res["xray_tokens"] if t["is_highlight"]]
        self.assertGreaterEqual(len(highlights), 4)
        print(f"[PASS] Test 2: Prize Spam X-Ray (Threat Score: {res['threat_score']}, Signals: {cat_types})")

    def test_03_bank_alert_phishing_analysis(self):
        """Verify bank alert triggers urgency, cta, and high risk protocol."""
        sample = "Your bank account has been temporarily suspended. Verify your account immediately at https://bank-verify.top"
        res = analyze_message_signals(sample, is_ml_spam=True, ml_confidence=0.985)
        
        cat_types = [s["type"] for s in res["risk_signals"]]
        self.assertIn("urgency", cat_types)
        self.assertIn("cta", cat_types)
        self.assertIn("url", cat_types)
        self.assertGreaterEqual(res["threat_score"], 75)
        print(f"[PASS] Test 3: Bank Alert Phishing X-Ray (Threat Score: {res['threat_score']}, Signals: {cat_types})")

    def test_04_promotional_sms_analysis(self):
        """Verify promotional SMS triggers promo signals."""
        sample = "Get 80% OFF today only. Shop now and claim your special offer."
        res = analyze_message_signals(sample, is_ml_spam=True, ml_confidence=0.88)
        
        cat_types = [s["type"] for s in res["risk_signals"]]
        self.assertIn("promo", cat_types)
        self.assertIn("urgency", cat_types)
        print(f"[PASS] Test 4: Promotional SMS X-Ray (Signals: {cat_types})")

    def test_05_normal_conversation_analysis(self):
        """Verify normal conversation yields minimal threat score and safe recommendations."""
        sample = "Hey, I'll meet you near the library at 4 PM."
        res = analyze_message_signals(sample, is_ml_spam=False, ml_confidence=0.999)
        
        self.assertLessEqual(res["threat_score"], 15)
        self.assertEqual(res["recommended_action"]["status"], "LOW_RISK")
        print(f"[PASS] Test 5: Normal Conversation (Threat Score: {res['threat_score']}, Safe Protocol)")

    def test_06_non_spam_with_currency_word(self):
        """Verify legitimate message mentioning money does not produce a high threat score."""
        sample = "Thanks for sending the cash for the movie tickets, I received it."
        res = analyze_message_signals(sample, is_ml_spam=False, ml_confidence=0.98)
        
        self.assertLessEqual(res["threat_score"], 30)
        self.assertEqual(res["recommended_action"]["status"], "LOW_RISK")
        print(f"[PASS] Test 6: Legitimate Message with Currency (Threat Score: {res['threat_score']})")

if __name__ == "__main__":
    unittest.main()
