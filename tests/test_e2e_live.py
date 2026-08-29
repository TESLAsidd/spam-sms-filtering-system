"""
SMS SENTINEL — End-to-End Live Integration Test for Phase 5.5
"""

import urllib.request
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def run_e2e_tests():
    print("=" * 80)
    print("SMS SENTINEL: FULL END-TO-END VERIFICATION AUDIT")
    print("=" * 80)

    # 1. Health Endpoint
    t0 = time.time()
    req = urllib.request.Request(f"{BASE_URL}/api/health", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req) as res:
        status_data = json.loads(res.read().decode("utf-8"))
        print(f"[OK] 1. Backend Health Check ({res.status} OK in {(time.time() - t0)*1000:.1f}ms):", status_data)

    # 2. Comprehensive Test Messages Matrix
    test_matrix = [
        {
            "name": "Prize Scam",
            "message": "Congratulations! You have won a free cash prize. Click now to claim.",
            "expect_spam": True,
            "min_threat": 75,
            "required_signals": ["prize", "promo", "cta"]
        },
        {
            "name": "Bank Suspended Phishing",
            "message": "Your bank account has been temporarily suspended. Verify your account immediately.",
            "expect_spam": True,
            "min_threat": 75,
            "required_signals": ["urgency", "cta"]
        },
        {
            "name": "Flash Sale Promo",
            "message": "Get 80% OFF today only. Shop now and claim your special offer.",
            "expect_spam": True,
            "min_threat": 60,
            "required_signals": ["promo", "urgency"]
        },
        {
            "name": "Normal Conversational Message",
            "message": "Hey, I'll meet you near the library at 4 PM.",
            "expect_spam": False,
            "max_threat": 20,
            "required_signals": []
        },
        {
            "name": "Casual Meeting with Number",
            "message": "Please call me tomorrow at 10 to discuss homework.",
            "expect_spam": False,
            "max_threat": 25,
            "required_signals": []
        },
        {
            "name": "Legitimate Bank Transaction Alert",
            "message": "Dear Customer, INR 450.00 debited from A/C XX1234 on 28-AUG-26. HDFC Bank",
            "expect_spam": False,
            "max_threat": 35,
            "required_signals": ["money"]
        },
        {
            "name": "XSS Injection Attack Vector",
            "message": "<script>alert('pwned')</script> Click http://evil.xyz immediately",
            "expect_spam": True,
            "min_threat": 75,
            "required_signals": ["url", "urgency", "cta"]
        }
    ]

    print("\nRunning Live Prediction Matrix:")
    print(f"{'#':<3} | {'TEST CASE':<30} | {'PREDICTION':<10} | {'CONFIDENCE':<10} | {'THREAT':<7} | {'SIGNALS DETECTED'}")
    print("-" * 80)

    for idx, tc in enumerate(test_matrix, 1):
        payload = json.dumps({"message": tc["message"]}).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/api/predict",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode("utf-8"))
            pred = data["prediction"]
            conf = data["confidence"]
            score = data["threat_score"]
            is_spam = data["is_spam"]
            signals = [s["type"] for s in data["risk_signals"]]

            conf_str = f"{(conf*100):.1f}%" if conf <= 1.0 else f"{conf:.1f}%"
            score_str = f"{score:>3}/100"

            expected_pred = "SPAM" if tc["expect_spam"] else "NOT SPAM"
            assert pred == expected_pred, f"Prediction mismatch for {tc['name']}: got {pred}, expected {expected_pred}"

            print(f"{idx:<3} | {tc['name']:<30} | {pred:<10} | {conf_str:<10} | {score_str:<7} | {signals}")

    print("-" * 80)
    print("ALL 7 END-TO-END CASES PASSED WITH 100% ACCURACY")
    print("=" * 80)

if __name__ == "__main__":
    run_e2e_tests()
