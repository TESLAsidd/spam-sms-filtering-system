"""
SMS SENTINEL — Phase 4 API & UI Integration Verification Script
"""

import urllib.request
import json

BASE_URL = "http://127.0.0.1:5000"

def test_api():
    print("=" * 70)
    print("PHASE 4: LIVE END-TO-END PREDICTION VERIFICATION")
    print("=" * 70)
    
    # 1. Health check
    req_health = urllib.request.Request(f"{BASE_URL}/api/health")
    with urllib.request.urlopen(req_health) as res:
        health_data = json.loads(res.read().decode("utf-8"))
        print("[OK] Health Check:", health_data)
        
    test_cases = [
        {
            "name": "Prize Scam",
            "message": "Congratulations! You have won a free cash prize. Click now to claim.",
            "expected": "SPAM"
        },
        {
            "name": "Normal Message",
            "message": "Hey, I'll meet you near the library at 4 PM.",
            "expected": "NOT SPAM"
        },
        {
            "name": "Bank Alert Phishing",
            "message": "Your bank account has been temporarily suspended. Verify your account immediately.",
            "expected": "SPAM"
        },
        {
            "name": "Promotion",
            "message": "Get 80% OFF today only. Shop now and claim your special offer.",
            "expected": "SPAM"
        }
    ]
    
    print("\nEvaluating Live Test Cases against POST /api/predict:")
    print(f"{'TEST CASE':<22} | {'EXPECTED':<10} | {'PREDICTED':<10} | {'CONFIDENCE':<10} | {'THREAT SCORE'}")
    print("-" * 70)
    
    for tc in test_cases:
        payload = json.dumps({"message": tc["message"]}).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}/api/predict",
            data=payload,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req) as res:
            data = json.loads(res.read().decode("utf-8"))
            pred = data.get("prediction")
            conf = data.get("confidence")
            score = data.get("threat_score")
            conf_str = f"{(conf * 100):.1f}%" if conf <= 1.0 else f"{conf:.1f}%"
            match_status = "[OK]" if pred == tc["expected"] else "[FAIL]"
            print(f"{tc['name']:<22} | {tc['expected']:<10} | {pred:<10} | {conf_str:<10} | {score:>3}/100 {match_status}")
            
    # 2. Test Edge Cases
    print("\nTesting Edge Cases:")
    # Empty message
    try:
        req_empty = urllib.request.Request(
            f"{BASE_URL}/api/predict",
            data=json.dumps({"message": ""}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req_empty)
    except urllib.error.HTTPError as e:
        print(f"[OK] Empty message correctly rejected with HTTP {e.code}")

    # Missing field
    try:
        req_missing = urllib.request.Request(
            f"{BASE_URL}/api/predict",
            data=json.dumps({"invalid": "text"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req_missing)
    except urllib.error.HTTPError as e:
        print(f"[OK] Missing 'message' field correctly rejected with HTTP {e.code}")

    print("=" * 70)

if __name__ == "__main__":
    test_api()
