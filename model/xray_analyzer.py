import re
import sys
import os
from typing import Dict, List, Any

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Deterministic Pattern Dictionaries for Risk Categories
RISK_CATEGORIES = {
    "prize": {
        "label": "Prize / Reward",
        "base_weight": 88,
        "patterns": [
            r"\b(?:won|winner|winning|prize|prizes|reward|rewards|lottery|jackpot|lucky draw|cash prize|bonus)\b",
            r"\bcongratulations\b",
            r"\bclaim(?:ed)?\s+now\b"
        ]
    },
    "urgency": {
        "label": "Urgency Indicator",
        "base_weight": 78,
        "patterns": [
            r"\b(?:urgent|urgently|immediately|immediate|act fast|expires|expiring|today only|last chance|final notice|within 24 hours|due today|suspended|blocked|blockage)\b",
            r"\blimited time\b",
            r"\bhurry\b"
        ]
    },
    "money": {
        "label": "Financial / Currency",
        "base_weight": 75,
        "patterns": [
            r"(?:[₹$£€]|INR|Rs\.?|USD|BTC)\s*[\d,]+(?:\.\d+)?(?:\s*(?:k|lakh|cr|thousand|million))?",
            r"\b(?:cash|money|dollars|rupees|credited|debited|payout|customs fee|refund|loan|transfer)\b"
        ]
    },
    "url": {
        "label": "Suspicious Link",
        "base_weight": 92,
        "patterns": [
            r"https?://[^\s<>\"']+",
            r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cli\.gs|cutt\.ly)/[^\s<>\"']*",
            r"\b[a-zA-Z0-9-]+\.(?:xyz|top|cc|club|live|info|work|click|link|stream|bid|icu|online)/[^\s<>\"']*"
        ]
    },
    "promo": {
        "label": "Promotional Lure",
        "base_weight": 68,
        "patterns": [
            r"\b(?:offer|offers|discount|discounts|sale|deals?|special offer|flat \d+% off|\d+% off|save big|promo|coupon|cashback)\b",
            r"\bfree\b"
        ]
    },
    "cta": {
        "label": "Call to Action",
        "base_weight": 70,
        "patterns": [
            r"\b(?:click|claim|verify|verification|confirm|confirmation|visit|submit|download|apply|redeem|reply stop|call now)\b"
        ]
    },
    "phone": {
        "label": "Direct Contact Number",
        "base_weight": 60,
        "patterns": [
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
        ]
    }
}

def extract_message_stats(text: str) -> Dict[str, Any]:
    """Calculates deterministic structural statistics from the raw SMS."""
    char_count = len(text)
    words = text.split()
    word_count = len(words)
    
    # URL extraction (unified with risk category patterns)
    url_pattern = r"https?://[^\s<>\"']+|\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cli\.gs|cutt\.ly)/[^\s<>\"']*|\b[a-zA-Z0-9-]+\.(?:xyz|top|cc|club|live|info|work|click|link|stream|bid|icu|online)/[^\s<>\"']*"
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    url_count = len(urls)
    
    # Phone number extraction (filter out short digit matches)
    raw_phones = re.findall(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", text)
    phone_candidates = [p for p in raw_phones if len(re.sub(r"\D", "", p)) >= 7]
    phone_count = len(phone_candidates)
    
    # Exclamation & Punctuation
    exclamation_count = text.count("!")
    question_count = text.count("?")
    
    # Capitalization ratio
    alpha_chars = [c for c in text if c.isalpha()]
    upper_chars = [c for c in alpha_chars if c.isupper()]
    uppercase_ratio = round((len(upper_chars) / len(alpha_chars) * 100), 1) if alpha_chars else 0.0
    
    return {
        "character_count": char_count,
        "word_count": word_count,
        "url_count": url_count,
        "phone_number_count": phone_count,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "uppercase_ratio": uppercase_ratio
    }

def analyze_message_signals(text: str, is_ml_spam: bool = False, ml_confidence: float = 1.0) -> Dict[str, Any]:
    """
    Performs secondary deterministic analysis of the SMS:
    - Identifies non-overlapping token highlights
    - Scores individual risk signal categories
    - Computes a deterministic Threat Score
    - Generates context-aware recommended actions
    """
    stats = extract_message_stats(text)
    
    detected_spans = [] # List of (start, end, category_key, matched_text)
    matched_categories = {}
    
    # 1. Pattern Matching & Span Extraction
    for cat_key, cat_data in RISK_CATEGORIES.items():
        matched_terms = set()
        for pat in cat_data["patterns"]:
            for match in re.finditer(pat, text, re.IGNORECASE):
                start, end = match.span()
                matched_str = text[start:end]
                # Filter out pure digits from phone regex if they are short numbers
                if cat_key == "phone" and len(re.sub(r"\D", "", matched_str)) < 7:
                    continue
                detected_spans.append({
                    "start": start,
                    "end": end,
                    "type": cat_key,
                    "label": cat_data["label"],
                    "term": matched_str
                })
                matched_terms.add(matched_str)
                
        if matched_terms:
            matched_categories[cat_key] = {
                "type": cat_key,
                "label": cat_data["label"],
                "base_weight": cat_data["base_weight"],
                "terms": list(matched_terms)
            }

    # 2. Resolve Overlapping Spans (prefer longer matches or higher priority)
    # Sort spans by start asc, length desc
    detected_spans.sort(key=lambda s: (s["start"], -(s["end"] - s["start"])))
    non_overlapping_spans = []
    occupied_indices = set()
    
    for span in detected_spans:
        span_range = set(range(span["start"], span["end"]))
        if not (span_range & occupied_indices):
            non_overlapping_spans.append(span)
            occupied_indices.update(span_range)

    # Re-sort spans by start index
    non_overlapping_spans.sort(key=lambda s: s["start"])

    # 3. Calculate Deterministic Signal Scores (0 - 100 scale)
    risk_signals = []
    total_signal_weight = 0
    
    for cat_key, cat_info in matched_categories.items():
        match_count = len(cat_info["terms"])
        # Score calculation: base_weight + bonus for multiple distinct triggers, capped at 99
        score = min(99, int(cat_info["base_weight"] + (match_count - 1) * 5))
        risk_signals.append({
            "type": cat_key,
            "label": cat_info["label"],
            "score": score,
            "terms": cat_info["terms"]
        })
        total_signal_weight += score

    # Sort signals descending by score
    risk_signals.sort(key=lambda s: -s["score"])

    # Total risk keyword count
    stats["risk_keyword_count"] = len(non_overlapping_spans)

    # 4. Deterministic Threat Score Calculation (0 - 100)
    # Based on number of risk categories present, presence of URLs, and uppercase ratio
    if is_ml_spam:
        base_threat = 75
        if "url" in matched_categories:
            base_threat += 12
        if "prize" in matched_categories:
            base_threat += 8
        if "urgency" in matched_categories:
            base_threat += 5
        if stats["uppercase_ratio"] > 30:
            base_threat += 3
        threat_score = min(100, max(70, base_threat))
    else:
        # For legitimate messages, signals remain informational and threat score stays low
        if len(risk_signals) == 0:
            threat_score = 4
        elif len(risk_signals) == 1:
            threat_score = min(25, int(risk_signals[0]["score"] * 0.25))
        else:
            threat_score = min(40, int((total_signal_weight / len(risk_signals)) * 0.35))

    # 5. Build Highlighted X-Ray Tokens Array (decomposed string pieces)
    xray_tokens = []
    last_idx = 0
    
    for span in non_overlapping_spans:
        # Preceding plain text
        if span["start"] > last_idx:
            plain_chunk = text[last_idx:span["start"]]
            xray_tokens.append({
                "text": plain_chunk,
                "is_highlight": False,
                "type": None,
                "label": None
            })
        # Highlighted span
        highlighted_chunk = text[span["start"]:span["end"]]
        xray_tokens.append({
            "text": highlighted_chunk,
            "is_highlight": True,
            "type": span["type"],
            "label": span["label"]
        })
        last_idx = span["end"]

    # Trailing plain text
    if last_idx < len(text):
        xray_tokens.append({
            "text": text[last_idx:],
            "is_highlight": False,
            "type": None,
            "label": None
        })

    # 6. Context-Aware Recommended Action
    if is_ml_spam or threat_score >= 60:
        recommended_action = {
            "status": "HIGH_RISK",
            "title": "SECURITY PROTOCOL RECOMMENDED",
            "badge": "DO NOT ENGAGE",
            "points": [
                "Do not click or open any links included in this message.",
                "Do not reply or call the sender's phone number.",
                "Never disclose passwords, OTPs, PINs, or banking details.",
                "Report and block the sender on your mobile carrier network."
            ]
        }
    elif threat_score >= 30:
        recommended_action = {
            "status": "MODERATE_RISK",
            "title": "PROCEED WITH CAUTION",
            "badge": "VERIFY SENDER",
            "points": [
                "Verify the sender's identity through official banking or service channels.",
                "Avoid clicking embedded links if you did not initiate the request.",
                "Check for spelling anomalies or unofficial domain extensions."
            ]
        }
    else:
        recommended_action = {
            "status": "LOW_RISK",
            "title": "NO ACTION REQUIRED",
            "badge": "SAFE MESSAGE",
            "points": [
                "No significant spam or smishing indicators were detected.",
                "Message appears to follow standard conversational or transactional patterns."
            ]
        }

    return {
        "threat_score": threat_score,
        "risk_signals": risk_signals,
        "message_stats": stats,
        "highlight_terms": non_overlapping_spans,
        "xray_tokens": xray_tokens,
        "recommended_action": recommended_action
    }

if __name__ == "__main__":
    sample = "Congratulations! You have won ₹50,000 CASH PRIZE. Click http://claim-now.com immediately."
    res = analyze_message_signals(sample, is_ml_spam=True, ml_confidence=0.999)
    print("X-Ray Analysis Result:")
    import pprint
    pprint.pprint(res)
