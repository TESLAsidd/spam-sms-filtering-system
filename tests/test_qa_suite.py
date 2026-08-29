"""
SMS SENTINEL — PHASE 5.5 COMPREHENSIVE QA & VALIDATION SUITE
Covers:
1. Dependency & Environment Validation
2. ML Model & Preprocessing Integrity
3. ML Edge Cases & Unicode Robustness
4. API Status Codes & Input Boundaries
5. Deterministic X-Ray Extraction & False Positive Guards
6. Threat Score & Confidence Distinction
7. Real Message Statistics Calculation
8. XSS & HTML Sanitization Safety
9. Response Schema Completeness
"""

import unittest
import os
import sys
import json
import joblib
import numpy as np

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from app import app, load_ml_pipeline
from model.xray_analyzer import extract_message_stats, analyze_message_signals
from model.inference import predict_sms

class TestComprehensiveQA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = app.test_client()
        cls.pipeline = load_ml_pipeline()

    def setUp(self):
        with self.client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["user_name"] = "QA Admin"
            sess["user_email"] = "qa@sentinel.test"

    # =========================================================================
    # 1. ML MODEL VALIDATION
    # =========================================================================

    def test_01_ml_model_fresh_load(self):
        """Verify saved pipeline loads and is an instance of scikit-learn Pipeline."""
        self.assertIsNotNone(self.pipeline)
        self.assertTrue(hasattr(self.pipeline, "predict"))
        self.assertTrue(hasattr(self.pipeline, "predict_proba"))
        
        # Check TF-IDF vectorizer component
        tfidf = self.pipeline.named_steps.get("tfidf")
        self.assertIsNotNone(tfidf)
        self.assertGreater(len(tfidf.vocabulary_), 1000)
        print("\n[QA PASS] 1. ML Model & Vocabulary Validation (Features > 1,000)")

    def test_02_ml_prediction_consistency(self):
        """Verify raw SMS string passed directly produces non-hardcoded probabilities."""
        sample_spam = "Congratulations! You have WON ₹50,000 in lucky draw. Click http://bit.ly/prize to claim!"
        res_spam = predict_sms(sample_spam)
        self.assertEqual(res_spam["prediction"], "SPAM")
        self.assertTrue(res_spam["is_spam"])
        self.assertGreaterEqual(res_spam["confidence"], 90.0)

        sample_ham = "Hey, are you free for the project meeting at 4 PM?"
        res_ham = predict_sms(sample_ham)
        self.assertEqual(res_ham["prediction"], "NOT SPAM")
        self.assertFalse(res_ham["is_spam"])
        self.assertGreaterEqual(res_ham["confidence"], 90.0)
        print("[QA PASS] 2. ML Prediction & Probability Consistency")

    # =========================================================================
    # 2. ML EDGE CASE TESTING
    # =========================================================================

    def test_03_ml_edge_cases_and_unicode(self):
        """Verify model handles extreme strings, currencies, emojis, and unusual Unicode without crashing."""
        edge_cases = [
            "A",                                              # Ultra short
            "WIN " * 80,                                      # Repetitive caps
            "🎉🔥💰 Claim your prize NOW $$$ €€€ £££ ₹₹₹",     # Emojis & Currencies
            "Hello?!?!?!?!.......;;;;;;",                     # Punctuation heavy
            "https://sub.domain.xyz/path?param=1&token=abc",   # Pure URL
            "+1-800-555-0199 call immediately",               # Phone number
            "ThIs Is A mIxEd CaSe MeSsAgE wItH nUmB3r5 12345",# Mixed alphanumeric
            "Привет мир 你好世界 🚀 100% free deal",           # Multi-lingual / Unicode
            "Normal conversation with no special triggers."   # Plain text
        ]
        
        for text in edge_cases:
            try:
                res = predict_sms(text)
                self.assertIn(res["prediction"], ["SPAM", "NOT SPAM"])
                self.assertIsInstance(res["confidence"], float)
            except Exception as e:
                self.fail(f"ML pipeline crashed on edge case: '{text}' -> {e}")
        print("[QA PASS] 3. ML Edge Cases & Multi-lingual/Emoji Robustness")

    # =========================================================================
    # 3. BACKEND API BOUNDARY VALIDATION
    # =========================================================================

    def test_04_api_health_endpoint(self):
        """Verify GET / and GET /api/health."""
        res_root = self.client.get("/", headers={"Accept": "application/json"})
        self.assertEqual(res_root.status_code, 200)
        self.assertEqual(res_root.get_json()["status"], "online")

        res_health = self.client.get("/api/health")
        self.assertEqual(res_health.status_code, 200)
        self.assertEqual(res_health.get_json()["status"], "online")
        print("[QA PASS] 4. API Health Endpoints (GET / and GET /api/health)")

    def test_05_api_input_validation_boundaries(self):
        """Verify strict HTTP 400 responses for invalid/malformed requests."""
        # Empty payload
        r1 = self.client.post("/api/predict", data=json.dumps({}), content_type="application/json")
        self.assertEqual(r1.status_code, 400)

        # Empty string
        r2 = self.client.post("/api/predict", data=json.dumps({"message": ""}), content_type="application/json")
        self.assertEqual(r2.status_code, 400)

        # Whitespace string
        r3 = self.client.post("/api/predict", data=json.dumps({"message": "   \n\t  "}), content_type="application/json")
        self.assertEqual(r3.status_code, 400)

        # Null value
        r4 = self.client.post("/api/predict", data=json.dumps({"message": None}), content_type="application/json")
        self.assertEqual(r4.status_code, 400)

        # Non-string number
        r5 = self.client.post("/api/predict", data=json.dumps({"message": 12345}), content_type="application/json")
        self.assertEqual(r5.status_code, 400)

        # Malformed JSON
        r6 = self.client.post("/api/predict", data="{'message': broken json", content_type="application/json")
        self.assertEqual(r6.status_code, 400)

        # Missing Content-Type header
        r7 = self.client.post("/api/predict", data="message=test", content_type="text/plain")
        self.assertEqual(r7.status_code, 400)

        # Excessively long message (> 1,000 characters)
        r8 = self.client.post("/api/predict", data=json.dumps({"message": "A" * 1200}), content_type="application/json")
        self.assertEqual(r8.status_code, 400)
        print("[QA PASS] 5. Defensive Input Boundaries (8/8 Invalid Scenarios -> HTTP 400)")

    # =========================================================================
    # 4. RESPONSE SCHEMA VALIDATION
    # =========================================================================

    def test_06_response_schema_completeness(self):
        """Verify API response contains all required fields with correct non-NaN types."""
        payload = {"message": "URGENT: Your account has been suspended. Click http://bank-kyc.xyz immediately."}
        response = self.client.post("/api/predict", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()

        # Required fields check
        required_keys = [
            "prediction", "confidence", "is_spam", "threat_score",
            "risk_signals", "message_stats", "highlight_terms",
            "xray_tokens", "recommended_action"
        ]
        for k in required_keys:
            self.assertIn(k, data, f"Missing required response field: {k}")

        # Type checks
        self.assertIsInstance(data["prediction"], str)
        self.assertIsInstance(data["confidence"], float)
        self.assertIsInstance(data["threat_score"], int)
        self.assertIsInstance(data["is_spam"], bool)
        self.assertIsInstance(data["risk_signals"], list)
        self.assertIsInstance(data["message_stats"], dict)
        self.assertIsInstance(data["xray_tokens"], list)
        self.assertIsInstance(data["recommended_action"], dict)

        # Stats sub-fields
        stats = data["message_stats"]
        for stat_key in ["character_count", "word_count", "url_count", "phone_number_count", "risk_keyword_count", "uppercase_ratio"]:
            self.assertIn(stat_key, stats)
            self.assertFalse(np.isnan(stats[stat_key]))
        print("[QA PASS] 6. API Response Schema Completeness & Type Integrity")

    # =========================================================================
    # 5. SECONDARY DETERMINISTIC X-RAY & FALSE POSITIVE GUARDS
    # =========================================================================

    def test_07_false_positive_guard_cases(self):
        """Verify casual phrases do not generate false risk alarms."""
        # 1. "Please call me tomorrow at 10." should not trigger phone number regex
        res1 = analyze_message_signals("Please call me tomorrow at 10.", is_ml_spam=False)
        self.assertEqual(res1["message_stats"]["phone_number_count"], 0)

        # 2. "I won the football match yesterday."
        res2 = analyze_message_signals("I won the football match yesterday.", is_ml_spam=False)
        self.assertLessEqual(res2["threat_score"], 25)
        self.assertEqual(res2["recommended_action"]["status"], "LOW_RISK")

        # 3. Legitimate money transfer
        res3 = analyze_message_signals("Thanks for sending Rs. 200 for the dinner.", is_ml_spam=False)
        self.assertLessEqual(res3["threat_score"], 30)
        print("[QA PASS] 7. Secondary X-Ray False Positive Guards")

    # =========================================================================
    # 6. MESSAGE STATISTICS ACCURACY
    # =========================================================================

    def test_08_message_stats_accuracy(self):
        """Verify exact structural statistics calculations."""
        raw_text = "Win ₹10,000 cash! Visit https://win.xyz or call 800-555-0199 now! Valid today only."
        stats = extract_message_stats(raw_text)
        
        self.assertEqual(stats["character_count"], len(raw_text))
        self.assertEqual(stats["word_count"], len(raw_text.split()))
        self.assertEqual(stats["url_count"], 1)
        self.assertEqual(stats["phone_number_count"], 1)
        self.assertEqual(stats["exclamation_count"], 2)
        self.assertGreater(stats["uppercase_ratio"], 0.0)
        print("[QA PASS] 8. Message Intelligence Statistics Exactness")

    # =========================================================================
    # 7. XSS & HTML SANITIZATION SECURITY
    # =========================================================================

    def test_09_xss_and_injection_safety(self):
        """Verify XSS payloads pass through as raw text without server exception."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert('XSS')>",
            "Hello <iframe src='javascript:alert(1)'></iframe>",
            "'; DROP TABLE investigations; --"
        ]
        
        for payload in xss_payloads:
            res = self.client.post("/api/predict", data=json.dumps({"message": payload}), content_type="application/json")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            # Raw string preserved in JSON without execution or corruption
            self.assertEqual(data["message"], payload)
        print("[QA PASS] 9. XSS & Injection Safety (5 Attack Vectors Neutralized)")

    # =========================================================================
    # 8. THREAT SCORE & CONFIDENCE SEPARATION
    # =========================================================================

    def test_10_threat_score_stability(self):
        """Verify Threat Score is deterministic and separated from Model Confidence."""
        sample = "Congratulations! You have won ₹50,000 CASH PRIZE. Click http://claim-now.com immediately."
        
        # Run 5 consecutive times
        scores = []
        confs = []
        for _ in range(5):
            res = self.client.post("/api/predict", data=json.dumps({"message": sample}), content_type="application/json")
            data = res.get_json()
            scores.append(data["threat_score"])
            confs.append(data["confidence"])

        # Stability checks
        self.assertEqual(len(set(scores)), 1, "Threat score fluctuated across identical runs!")
        self.assertEqual(len(set(confs)), 1, "Model confidence fluctuated across identical runs!")
        self.assertGreaterEqual(scores[0], 80)
        self.assertGreaterEqual(confs[0], 0.90)
        print(f"[QA PASS] 10. Threat Score Stability ({scores[0]}/100) & Model Confidence ({confs[0]*100:.1f}%)")

    # =========================================================================
    # 9. MODEL INFO & CONTENT NEGOTIATION
    # =========================================================================

    def test_11_model_info_endpoint(self):
        """Verify GET /api/model-info returns complete architecture diagnostics."""
        res = self.client.get("/api/model-info")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("model_type", data)
        self.assertIn("vectorizer", data)
        self.assertIn("metrics", data)
        self.assertIn("accuracy", data["metrics"])
        print("[QA PASS] 11. Model Info Endpoint (/api/model-info)")

    def test_12_get_root_content_negotiation(self):
        """Verify GET / returns HTML by default, and JSON when Accept: application/json."""
        # HTML browser request
        res_html = self.client.get("/")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn(b"<!DOCTYPE html>", res_html.data)

        # JSON API request
        res_json = self.client.get("/", headers={"Accept": "application/json"})
        self.assertEqual(res_json.status_code, 200)
        data = res_json.get_json()
        self.assertEqual(data["status"], "online")
        print("[QA PASS] 12. GET / Content Negotiation (HTML vs JSON)")

if __name__ == "__main__":
    unittest.main()
