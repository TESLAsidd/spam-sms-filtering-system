"""
SMS SENTINEL - Predictor & Intelligence Engine
Combines real Multinomial Naive Bayes ML classification with a deterministic
Risk Signal & Token-Level X-Ray Analyzer.
"""

import os
import re
import json
import numpy as np
import joblib

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")
METADATA_PATH = os.path.join(MODEL_DIR, "metadata.json")

# Global singleton cache
_MODEL = None
_VECTORIZER = None
_METADATA = None

def load_artifacts():
    """Load model, vectorizer, and metadata into memory."""
    global _MODEL, _VECTORIZER, _METADATA
    if _MODEL is None:
        if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
            raise FileNotFoundError("Model artifacts missing. Run `python train_model.py` first.")
        _MODEL = joblib.load(MODEL_PATH)
        _VECTORIZER = joblib.load(VECTORIZER_PATH)
        if os.path.exists(METADATA_PATH):
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                _METADATA = json.load(f)
        else:
            _METADATA = {"model_type": "Multinomial Naive Bayes"}
    return _MODEL, _VECTORIZER, _METADATA

# Signal Rule Definitions (Regex Patterns & Metadata)
SIGNAL_PATTERNS = {
    "monetary": {
        "label": "Money / Reward",
        "description": "Financial promises, currency amounts, or prize vouchers",
        "severity": "high",
        "regex": r'(?:[₹$£€]\s*[\d,]+(?:\.\d+)?|\b\d+\s*(?:lakh|crore|thousand|hundred|usd|inr|eur|gbp)\b|\b(?:cash|reward|payout|refund|credit|bonus|jackpot|wealth|prize money)\b)',
        "base_weight": 25
    },
    "urgency": {
        "label": "Urgency & Threat",
        "description": "High-pressure urgency, expiration deadlines, or account suspension warnings",
        "severity": "high",
        "regex": r'\b(?:urgent|urgently|immediately|immediately|expires|expiring|suspended|deactivated|blocked|discontinued|final notice|24 hours|legal action|penalty|action required|tonight)\b',
        "base_weight": 25
    },
    "url_link": {
        "label": "Suspicious Link",
        "description": "Embedded hyperlinks, deceptive shortlinks, or unusual domain extensions",
        "severity": "high",
        "regex": r'(?:https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9-]+\.(?:xyz|top|cc|tk|ml|ga|cf|gq|site|link|info|work|club|app|live|to|me|bit\.ly|t\.me|tinyurl\.com)[/\w\.-]*)',
        "base_weight": 30
    },
    "promotional": {
        "label": "Promotional Signal",
        "description": "Aggressive marketing, sweepstakes, or unverified claims",
        "severity": "medium",
        "regex": r'\b(?:congratulations|congrats|winner|won|free entry|free gift|gift card|voucher|exclusive offer|100% free|no deposit|discount|flash sale|limited stock|guaranteed)\b',
        "base_weight": 20
    },
    "harvesting": {
        "label": "Data / Credential Harvesting",
        "description": "Requests for authentication, sensitive credentials, KYC, or PINs",
        "severity": "high",
        "regex": r'\b(?:kyc|otp|password|pin|biometric|verify|verification|update details|bank account|credit card|debit card|ssn|aadhaar|pan card|login now)\b',
        "base_weight": 30
    },
    "call_to_action": {
        "label": "Call to Action",
        "description": "Direct instructions to dial, reply, or click",
        "severity": "low",
        "regex": r'\b(?:click here|click|call now|call|dial|reply stop|reply yes|whatsapp|apply now|redeem now|redeem|tap here|claim now|claim)\b',
        "base_weight": 15
    },
    "phone_contact": {
        "label": "Direct Contact / Phone",
        "description": "Phone numbers, international toll-free formats, or shortcodes",
        "severity": "medium",
        "regex": r'(?:\+\d{1,3}[\s-]?\d{4,12}|\b\d{10}\b|\b1800[\s-]?\d{3,7}\b|\b\d{5,6}\b)',
        "base_weight": 15
    }
}

def clean_text(text: str) -> str:
    """Standard text normalization."""
    if not isinstance(text, str):
        return ""
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()

def extract_message_stats(text: str) -> dict:
    """Compute deterministic text metrics."""
    char_count = len(text)
    words = re.findall(r'\b\w+\b', text)
    word_count = len(words)
    
    # URL extraction
    urls = re.findall(r'https?://\S+|www\.\S+|[a-zA-Z0-9-]+\.(?:xyz|top|cc|tk|site|link|info|work|club|app|live|to|me|bit\.ly|t\.me|tinyurl\.com)\b', text, re.IGNORECASE)
    url_count = len(urls)
    
    # Phone numbers / shortcodes
    phones = re.findall(r'\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{10}\b|\b1800\d{6}\b', text)
    phone_count = len(phones)
    
    # Uppercase analysis
    letters = [c for c in text if c.isalpha()]
    upper_letters = [c for c in text if c.isupper()]
    uppercase_ratio = round((len(upper_letters) / len(letters) * 100), 1) if letters else 0.0
    
    # Exclamations and special punctuation
    exclamation_count = text.count('!')
    question_count = text.count('?')
    digits = [c for c in text if c.isdigit()]
    
    return {
        "char_count": char_count,
        "word_count": word_count,
        "url_count": url_count,
        "phone_count": phone_count,
        "uppercase_ratio": uppercase_ratio,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "digit_count": len(digits),
        "has_high_caps": uppercase_ratio > 30.0 and len(letters) > 10,
        "has_excessive_punctuation": exclamation_count >= 3
    }

def detect_risk_signals(text: str) -> list:
    """Scan text for predefined threat patterns and calculate relative intensities."""
    detected = []
    text_lower = text.lower()
    
    for sig_key, config in SIGNAL_PATTERNS.items():
        matches = list(set(re.findall(config["regex"], text, re.IGNORECASE)))
        if matches:
            # Calculate intensity score (20 to 100) based on match frequency
            count = len(matches)
            intensity = min(100, config["base_weight"] + (count - 1) * 20)
            
            # Extract sample text snippets
            clean_matches = [m.strip() if isinstance(m, str) else str(m) for m in matches[:4]]
            
            detected.append({
                "key": sig_key,
                "label": config["label"],
                "description": config["description"],
                "severity": config["severity"],
                "matches": clean_matches,
                "count": count,
                "intensity": int(intensity)
            })
            
    # Sort detected signals by severity and intensity
    severity_order = {"high": 3, "medium": 2, "low": 1}
    detected.sort(key=lambda x: (severity_order.get(x["severity"], 0), x["intensity"]), reverse=True)
    return detected

def generate_xray_tokens(text: str, detected_signals: list) -> list:
    """
    Produce a token-level decomposition of the SMS text with precise character spans
    and category labels for the interactive Message X-Ray view.
    """
    if not text:
        return []

    # Map of all matched substrings and their tags
    spans = []
    for sig in detected_signals:
        for match in sig["matches"]:
            if not match:
                continue
            # Find all occurrences in original text
            start = 0
            while True:
                idx = text.lower().find(match.lower(), start)
                if idx == -1:
                    break
                end = idx + len(match)
                spans.append({
                    "start": idx,
                    "end": end,
                    "category": sig["key"],
                    "label": sig["label"],
                    "severity": sig["severity"],
                    "matched_text": text[idx:end]
                })
                start = idx + 1

    # Merge overlapping spans or pick highest severity
    spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))
    
    non_overlapping = []
    current_end = -1
    for s in spans:
        if s["start"] >= current_end:
            non_overlapping.append(s)
            current_end = s["end"]
            
    # Build token stream covering the entire text
    tokens = []
    cursor = 0
    for s in non_overlapping:
        # Preceding normal text
        if s["start"] > cursor:
            normal_chunk = text[cursor:s["start"]]
            tokens.append({
                "text": normal_chunk,
                "is_signal": False,
                "category": None,
                "label": None,
                "severity": None
            })
        # Highlighted signal chunk
        tokens.append({
            "text": text[s["start"]:s["end"]],
            "is_signal": True,
            "category": s["category"],
            "label": s["label"],
            "severity": s["severity"]
        })
        cursor = s["end"]

    # Trailing normal text
    if cursor < len(text):
        tokens.append({
            "text": text[cursor:],
            "is_signal": False,
            "category": None,
            "label": None,
            "severity": None
        })

    return tokens

def get_recommended_action(is_spam: bool, threat_level: str, signals: list) -> dict:
    """Generate context-aware, security recommendations."""
    if is_spam or threat_level == "HIGH RISK":
        has_url = any(s["key"] == "url_link" for s in signals)
        has_harvesting = any(s["key"] == "harvesting" for s in signals)
        has_money = any(s["key"] == "monetary" for s in signals)

        points = [
            "Do not reply or click any links in this message.",
            "Avoid sharing OTPs, passwords, or personal identity details."
        ]
        if has_url:
            points.append("The embedded link may lead to a credential-harvesting phishing page.")
        if has_harvesting or has_money:
            points.append("Legitimate financial organizations never request sensitive credentials via SMS.")
        points.append("Block the sender and report this message as spam/phishing.")

        return {
            "title": "THREAT MITIGATION PROTOCOL",
            "action_type": "danger",
            "badge": "IMMEDIATE CAUTION",
            "points": points
        }
    elif threat_level == "MEDIUM RISK":
        return {
            "title": "EXERCISE CAUTION",
            "action_type": "warning",
            "badge": "SUSPICIOUS SIGNALS DETECTED",
            "points": [
                "This message exhibits promotional or unsolicited characteristics.",
                "Verify the sender's identity through official channels before taking action.",
                "Never share verification codes or banking pins."
            ]
        }
    else:
        return {
            "title": "NO SECURITY ACTION REQUIRED",
            "action_type": "safe",
            "badge": "CLEAN MESSAGE",
            "points": [
                "No critical phishing, fraud, or spam indicators were detected.",
                "Message exhibits patterns consistent with legitimate communications."
            ]
        }

def analyze_sms(message: str) -> dict:
    """
    Main analysis pipeline:
    1. Text validation & cleaning
    2. ML Feature extraction (TF-IDF) & Naive Bayes inference
    3. Deterministic risk signal extraction & stats computation
    4. Threat score synthesis
    5. X-Ray tokenization
    6. Pipeline diagnostic trace generation
    """
    if not message or not message.strip():
        raise ValueError("SMS message cannot be empty.")
    
    if len(message) > 1000:
        raise ValueError("SMS message exceeds maximum length limit of 1000 characters.")

    model, vectorizer, metadata = load_artifacts()

    raw_text = message.strip()
    cleaned = clean_text(raw_text)

    # 1. TF-IDF feature extraction
    tfidf_vec = vectorizer.transform([cleaned])
    
    # 2. Naive Bayes probability
    probabilities = model.predict_proba(tfidf_vec)[0]
    classes = list(model.classes_)
    spam_idx = classes.index("spam")
    ham_idx = classes.index("ham")
    
    prob_spam = float(probabilities[spam_idx])
    prob_ham = float(probabilities[ham_idx])
    
    # Raw ML prediction
    ml_prediction = "spam" if prob_spam >= 0.5 else "ham"
    raw_confidence = round(max(prob_spam, prob_ham) * 100, 1)

    # 3. Extract active TF-IDF features with weights for this specific message
    feature_names = np.array(vectorizer.get_feature_names_out())
    nonzero_indices = tfidf_vec.nonzero()[1]
    active_features = []
    
    for idx in nonzero_indices:
        feat_name = feature_names[idx]
        weight = float(tfidf_vec[0, idx])
        # Calculate spam log-likelihood ratio for this word
        spam_log = float(model.feature_log_prob_[spam_idx, idx])
        ham_log = float(model.feature_log_prob_[ham_idx, idx])
        llr = round(spam_log - ham_log, 3)
        active_features.append({
            "term": feat_name,
            "tfidf_weight": round(weight, 4),
            "log_likelihood_ratio": llr,
            "indicates": "spam" if llr > 0 else "ham"
        })
    active_features.sort(key=lambda x: x["tfidf_weight"], reverse=True)

    # 4. Deterministic Risk Signal Extraction & Text Stats
    signals = detect_risk_signals(raw_text)
    stats = extract_message_stats(raw_text)
    stats["risk_keyword_count"] = sum(s["count"] for s in signals)

    # 5. Threat Score Calibration (0 to 100)
    # Blend Naive Bayes posterior probability with signal density
    signal_score_sum = sum(s["intensity"] for s in signals)
    signal_factor = min(35, signal_score_sum * 0.3)

    if prob_spam >= 0.5:
        # Scale spam probability (0.5 -> 1.0) to baseline (65 -> 95) + signal factor
        base_score = 65 + (prob_spam - 0.5) * 60
        threat_score = int(np.clip(base_score + signal_factor * 0.5, 65, 99))
        threat_level = "HIGH RISK"
        is_spam = True
        display_prediction = "SPAM"
        confidence = round(prob_spam * 100, 1)
    else:
        # Scale ham probability
        base_score = prob_spam * 40
        threat_score = int(np.clip(base_score + signal_factor * 0.4, 3, 58))
        if threat_score >= 40 or len(signals) >= 2:
            threat_level = "MEDIUM RISK"
        else:
            threat_level = "LOW RISK"
        is_spam = False
        display_prediction = "NOT SPAM"
        confidence = round(prob_ham * 100, 1)

    # 6. Interactive Message X-Ray
    xray_tokens = generate_xray_tokens(raw_text, signals)

    # 7. Recommended Action
    recommended_action = get_recommended_action(is_spam, threat_level, signals)

    # 8. Complete Pipeline Diagnostic Trace (for Investigation Mode in presentations/vivas)
    pipeline_trace = {
        "step_1_input": {
            "raw_message": raw_text,
            "char_length": len(raw_text),
            "word_count": stats["word_count"]
        },
        "step_2_preprocessing": {
            "normalized_text": cleaned,
            "transformations": [
                "Unicode normalization",
                "Whitespace compaction",
                "Lowercasing",
                "Regex token extraction"
            ]
        },
        "step_3_tfidf": {
            "vectorizer": "TF-IDF (1-2 N-Grams)",
            "vocabulary_size": metadata.get("vocabulary_size", 5000),
            "active_terms_count": len(active_features),
            "top_extracted_terms": active_features[:8]
        },
        "step_4_naive_bayes": {
            "algorithm": "Multinomial Naive Bayes",
            "smoothing_alpha": metadata.get("alpha", 0.1),
            "posterior_probabilities": {
                "spam": round(prob_spam, 4),
                "ham": round(prob_ham, 4)
            },
            "class_decision": display_prediction,
            "confidence_percent": confidence
        },
        "step_5_risk_engine": {
            "detected_signals_count": len(signals),
            "signals": [s["label"] for s in signals],
            "threat_score": threat_score,
            "threat_level": threat_level
        },
        "step_6_verdict": {
            "verdict": display_prediction,
            "is_spam": is_spam,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "confidence": confidence
        }
    }

    return {
        "prediction": display_prediction,
        "is_spam": is_spam,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "confidence": confidence,
        "signals": signals,
        "message_stats": stats,
        "xray_tokens": xray_tokens,
        "pipeline_trace": pipeline_trace,
        "recommended_action": recommended_action,
        "raw_message": raw_text
    }

if __name__ == "__main__":
    # Self-test predictor
    sample_spam = "Congratulations! You have WON ₹50,000 in the lucky draw. Click http://bit.ly/prize immediately to claim your cash reward!"
    sample_ham = "Hey, are you coming to the college library today? Let me know so I can save a seat for you."
    
    print("Testing Spam Sample:")
    res_spam = analyze_sms(sample_spam)
    print(f"  Prediction: {res_spam['prediction']} ({res_spam['threat_level']}), Score: {res_spam['threat_score']}, Confidence: {res_spam['confidence']}%")
    print(f"  Signals: {[s['label'] for s in res_spam['signals']]}")
    
    print("\nTesting Ham Sample:")
    res_ham = analyze_sms(sample_ham)
    print(f"  Prediction: {res_ham['prediction']} ({res_ham['threat_level']}), Score: {res_ham['threat_score']}, Confidence: {res_ham['confidence']}%")
    print(f"  Signals: {[s['label'] for s in res_ham['signals']]}")
