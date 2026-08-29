"""
SMS SENTINEL - Model Training Pipeline
Trains a Multinomial Naive Bayes classifier on TF-IDF features for SMS Spam Detection.
Serializes model artifacts to `model/model.pkl`, `model/vectorizer.pkl`, and `model/metadata.json`.
"""

import os
import json
import re
import urllib.request
import zipfile
import io
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

def clean_text(text: str) -> str:
    """Standard text normalization for SMS preprocessing."""
    if not isinstance(text, str):
        return ""
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    return text.lower()

def get_fallback_dataset() -> pd.DataFrame:
    """
    Curated high-signal dataset covering diverse SMS spam categories
    (financial, smishing, lottery, urgent OTP, delivery phishing, crypto, promo)
    and legitimate ham messages (conversations, transactional bank SMS, notifications).
    """
    data = [
        # --- SPAM SAMPLES ---
        ("spam", "Congratulations! You have WON ₹50,000 in the grand lucky draw. Click http://bit.ly/prize-claim immediately to claim your cash reward!"),
        ("spam", "URGENT: Your SBI Bank account has been SUSPENDED due to incomplete KYC. Update your details immediately at https://sbi-kyc-update.xyz to avoid permanent blockage."),
        ("spam", "Dear Customer, You have won $1,000,000 in the British National Lottery! Call +447911123456 with reference code BNL889 to receive your payout."),
        ("spam", "ALERT: Unauthorized login attempt detected from IP 192.168.1.1. Verify your Apple ID password now at https://appleid-security-verify.net or account will be locked."),
        ("spam", "Exclusive Offer! Get 90% discount on all luxury watches today only. Limited stock available. Visit http://lux-sale.top/shop now! Reply STOP to opt out."),
        ("spam", "You have an unclaimed parcel waiting at our distribution center. Pay $2.99 customs fee at https://post-parcel-track.cc/pay within 24 hours to schedule delivery."),
        ("spam", "Guaranteed 500% returns in 7 days! Invest in Bitcoin with our automated AI bot. WhatsApp +18005550199 to start trading with just $50."),
        ("spam", "HDFC Bank Alert: ₹25,000 has been debited from your A/C. If this was not you, cancel transaction immediately at https://hdfc-fraud-alert.co/reversal"),
        ("spam", "Congratulations Winner! Your mobile number won 2nd prize in Diwali Dhamaka. Call +919876543210 to claim your gold coin voucher."),
        ("spam", "Final Notice: Your electricity connection will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer immediately at 9876501234."),
        ("spam", "Work from home and earn ₹3,000 to ₹8,000 daily using your smartphone! No experience needed. Click https://t.me/easy-jobs-india to join."),
        ("spam", "Free Entry to VIP Casino Club! Deposit $10 and get $100 FREE bonus cash today. Click https://vip-spin-win.club to play now!"),
        ("spam", "Your Netflix subscription has expired. Payment declined. Update your credit card info at https://netflix-billing-renew.org to keep watching."),
        ("spam", "URGENT: Income Tax Refund of ₹15,400 approved. Click https://incometax-refund-gov.in/claim to enter your bank account and receive direct transfer."),
        ("spam", "Hey sexy, I saw your profile and loved your photos! Check out my private webcam video at http://hot-cam-girls.top/cam?id=883"),
        ("spam", "ICICI Alert: Your credit card reward points (worth ₹8,990) expire today! Redeem for cash at https://icici-rewards-redeem.cc"),
        ("spam", "Dear user, you have been selected for Amazon Prime $500 Gift Card reward. Complete quick 1-minute survey at https://amzn-gift-reward.site to claim."),
        ("spam", "Urgent security check: Your WhatsApp account will be deactivated in 6 hours. Verify your phone number at https://wa-verify-service.net"),
        ("spam", "Get pre-approved personal loan up to ₹10,00,000 with 0% interest for 6 months! Instant disbursal. Apply now at http://fast-loan-app.xyz"),
        ("spam", "Win a brand new iPhone 15 Pro Max! You are one of 5 lucky contestants chosen. Click https://apple-promo-winner.cc to enter shipping address."),
        ("spam", "Paytm KYC Alert: Your wallet is blocked. Tap https://paytm-kyc-support.top to complete biometric verification within 24 hours."),
        ("spam", "Attention: Legal action initiated against your social security number due to tax evasion. Call Federal Officer at 800-555-0144 immediately."),
        ("spam", "Double your Ethereum instantly! Send 0.1 ETH to receive 0.5 ETH back from Elon Musk giveaway. Visit https://eth-event-promo.net"),
        ("spam", "Claim your free Walmart $1000 shopping spree voucher now! Reply YES to 88202 or visit http://walmart-spree.com/free"),
        ("spam", "Action Required: Suspicious debit card charge of $499.00 at Walmart. If unauthorized, click https://fraud-protection-desk.link/verify to freeze card."),
        ("spam", "FLAT 80% OFF on Nike, Adidas & Puma shoes. Today only flash sale! Use code SUPER80 at checkout https://sneaker-outlet-sale.xyz"),
        ("spam", "Hi, this is Jessica. Are we still meeting for lunch tomorrow? Check my location here: http://track-gps-locate.me/jessica"),
        ("spam", "Free spins on slot machines! No deposit required. Claim $50 free chips right now at https://vegas-royal-casino.top"),
        ("spam", "Your vehicle registration has expired. Avoid heavy penalty by paying $15 fine online at https://dmv-license-renew.info/pay"),
        ("spam", "Congratulations! You've been pre-selected for ₹5 Lakh health insurance cover with zero paperwork. Call 1800-999-888 to activate."),

        # --- HAM SAMPLES ---
        ("ham", "Hey, are you coming to the college library today? Let me know so I can save a seat for you."),
        ("ham", "Hi Dad, I reached the hostel safely. The train was on time. Will call you after dinner."),
        ("ham", "Dear Customer, INR 450.00 debited from A/C XX1234 on 28-AUG-26 at CAFE COFFEE DAY via UPI Ref 629104829104. - HDFC Bank"),
        ("ham", "Your One Time Password (OTP) for logging into Swiggy is 492018. Valid for 10 minutes. Do not share this OTP with anyone."),
        ("ham", "Can we reschedule our project sync meeting to 4:30 PM? The professor called for a quick department update."),
        ("ham", "Your order #84920 from Amazon has been shipped via BlueDart and is expected to arrive by tomorrow, 3 PM. Track: https://amazon.in/orders"),
        ("ham", "Hey! Thanks for helping out with the presentation slides yesterday. Professor Sharma really liked our diagram."),
        ("ham", "Hi Priya, don't forget to submit the database assignment before midnight today on Google Classroom."),
        ("ham", "Your Uber driver Ramesh (KA-01-AB-1234) is arriving in 3 mins. PIN for ride: 8821."),
        ("ham", "Dear user, your OTP for HDFC NetBanking login is 738192. Do not share it with bank staff or anyone else."),
        ("ham", "Are we still playing football in the evening? Rahul said the ground might be wet after the rain."),
        ("ham", "Mom asked if you need any groceries from the supermarket before she heads back home."),
        ("ham", "Your Airtel broadband bill for August is ₹1,178. Paid successfully on 27-Aug. Thank you for choosing Airtel."),
        ("ham", "Hey man, send me the notes for compiler design module 3 when you get a chance. Thanks!"),
        ("ham", "Flight AI-504 from Bangalore to Delhi is scheduled on time at 18:20 hrs from Terminal 2, Gate 14."),
        ("ham", "Happy birthday Vikram! Wishing you a fantastic year ahead filled with joy, health and success!"),
        ("ham", "Hi team, please find attached the meeting minutes and action items from our weekly sprint review."),
        ("ham", "Your appointment with Dr. Mehta at Apollo Hospital is confirmed for Friday, 4:00 PM."),
        ("ham", "I left my keys on the kitchen table. Could you please lock the main door when you leave?"),
        ("ham", "Dear Customer, ₹15,000.00 credited to your A/C XX9876 on 28-AUG-26 towards Salary by XYZ Tech. - ICICI Bank"),
        ("ham", "Let's grab lunch at the canteen around 1:15 PM once the lab session gets over."),
        ("ham", "Hey, did you check out the new research paper on transformers that Dr. Alan shared in the group?"),
        ("ham", "Your package from Flipkart has been delivered to your doorstep. Thank you for shopping with us."),
        ("ham", "Please review the pull request on GitHub when you have 10 minutes. Added error handling for the API."),
        ("ham", "Hi Rohan, the class test for Operating Systems is postponed to next Tuesday as per the faculty notice."),
        ("ham", "Your Zomato delivery partner is on the way with your food order. Estimated arrival: 15 mins."),
        ("ham", "Thanks for the birthday gift! Loved the book you picked out. Let's catch up this weekend."),
        ("ham", "Dear User, 50% daily data quota consumed on your Jio number 9876543210. Renew at jio.com"),
        ("ham", "Hey, let me know when you reach home. Text me so I know you got back safe."),
        ("ham", "The seminar on Cyber Security & Machine Learning will begin at 10:00 AM sharp in Auditorium B.")
    ]

    # Replicate with minor variations to generate robust foundational sample weights
    augmented = []
    for label, msg in data:
        augmented.append((label, msg))
        if label == "spam":
            # Add variation
            augmented.append((label, f"URGENT ALERT: {msg}"))
            augmented.append((label, f"Notification: {msg} Click immediately!"))
        else:
            augmented.append((label, f"Reminder: {msg}"))
            augmented.append((label, f"Hi, {msg}"))

    return pd.DataFrame(augmented, columns=["label", "message"])

def download_or_load_dataset() -> pd.DataFrame:
    """
    Attempts to download the authoritative SMS Spam Collection dataset from UCI/GitHub.
    Falls back gracefully to the curated dataset if network is unavailable.
    """
    url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
    try:
        print(f"Attempting to download SMS Spam Collection dataset from {url}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as response:
            content = response.read().decode('utf-8', errors='ignore')
            lines = [line.split('\t') for line in content.strip().split('\n') if '\t' in line]
            df = pd.DataFrame(lines, columns=["label", "message"])
            print(f"Successfully loaded standard dataset with {len(df)} records.")
            
            # Combine with our modern smishing/crypto/OTP samples to enrich the model
            fallback = get_fallback_dataset()
            combined = pd.concat([df, fallback], ignore_index=True)
            print(f"Enriched dataset with modern scam patterns: Total {len(combined)} records.")
            return combined
    except Exception as e:
        print(f"Network download failed ({e}). Using rich curated dataset...")
        fallback = get_fallback_dataset()
        # Expand dataset size with permutations
        return fallback

def train_and_export():
    print("=" * 60)
    print("SMS SENTINEL - MODEL TRAINING PIPELINE")
    print("=" * 60)

    # 1. Prepare output directory
    model_dir = os.path.join(os.path.dirname(__file__), "model")
    os.makedirs(model_dir, exist_ok=True)

    # 2. Load dataset
    df = download_or_load_dataset()
    df["label"] = df["label"].str.strip().str.lower()
    df["message"] = df["message"].astype(str)
    
    # Filter valid rows
    df = df[df["label"].isin(["ham", "spam"])].dropna()
    print(f"Total samples: {len(df)} (Ham: {sum(df['label'] == 'ham')}, Spam: {sum(df['label'] == 'spam')})")

    # 3. Clean and preprocess
    df["cleaned"] = df["message"].apply(clean_text)

    # 4. Train-Test Split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        df["cleaned"],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"]
    )

    # 5. TF-IDF Feature Extraction
    print("Fitting TF-IDF Vectorizer (ngram_range=(1, 2), max_features=5000)...")
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True,
        stop_words="english",
        min_df=1
    )
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    # 6. Train Multinomial Naive Bayes Classifier
    print("Training Multinomial Naive Bayes (alpha=0.1)...")
    model = MultinomialNB(alpha=0.1)
    model.fit(X_train_tfidf, y_train)

    # 7. Evaluate Model Performance
    y_pred = model.predict(X_test_tfidf)
    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, pos_label="spam")
    rec = recall_score(y_test, y_pred, pos_label="spam")
    f1 = f1_score(y_test, y_pred, pos_label="spam")
    cm = confusion_matrix(y_test, y_pred, labels=["ham", "spam"]).tolist()

    print("\n--- Model Evaluation Metrics ---")
    print(f"Accuracy  : {acc * 100:.2f}%")
    print(f"Precision : {prec * 100:.2f}%")
    print(f"Recall    : {rec * 100:.2f}%")
    print(f"F1-Score  : {f1 * 100:.2f}%")
    print(f"Confusion Matrix (Ham/Spam): {cm}")

    # 8. Extract top indicative spam features for transparency/diagnostics
    feature_names = np.array(vectorizer.get_feature_names_out())
    # log P(w | spam) - log P(w | ham)
    spam_idx = list(model.classes_).index("spam")
    ham_idx = list(model.classes_).index("ham")
    log_ratio = model.feature_log_prob_[spam_idx] - model.feature_log_prob_[ham_idx]
    top_spam_indices = np.argsort(log_ratio)[-20:][::-1]
    top_spam_features = [
        {"feature": feature_names[i], "log_ratio": float(round(log_ratio[i], 3))}
        for i in top_spam_indices
    ]

    # 9. Save artifacts to model directory
    model_path = os.path.join(model_dir, "model.pkl")
    vectorizer_path = os.path.join(model_dir, "vectorizer.pkl")
    metadata_path = os.path.join(model_dir, "metadata.json")

    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)

    metadata = {
        "model_type": "Multinomial Naive Bayes",
        "alpha": 0.1,
        "vectorizer_type": "TF-IDF Vectorizer",
        "ngram_range": [1, 2],
        "max_features": 5000,
        "vocabulary_size": len(vectorizer.vocabulary_),
        "total_dataset_size": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "metrics": {
            "accuracy": round(float(acc) * 100, 2),
            "precision": round(float(prec) * 100, 2),
            "recall": round(float(rec) * 100, 2),
            "f1_score": round(float(f1) * 100, 2),
            "confusion_matrix": cm
        },
        "classes": list(model.classes_),
        "top_spam_features": top_spam_features
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nModel artifacts saved successfully:")
    print(f"  -> {model_path}")
    print(f"  -> {vectorizer_path}")
    print(f"  -> {metadata_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_and_export()
