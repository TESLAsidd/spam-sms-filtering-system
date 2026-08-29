import os
import sys
import joblib

if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

MODEL_PATH = os.path.join(os.path.dirname(__file__), "spam_classifier.pkl")

# Cached Pipeline Singleton
_PIPELINE = None

def get_pipeline():
    """Load and cache the trained Scikit-learn Pipeline from disk."""
    global _PIPELINE
    if _PIPELINE is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Trained pipeline artifact not found at: {MODEL_PATH}. "
                "Please run `python train_ml_engine.py` first."
            )
        _PIPELINE = joblib.load(MODEL_PATH)
    return _PIPELINE

def predict_sms(message: str) -> dict:
    """
    Accepts one raw SMS message string and returns prediction and confidence.
    
    Args:
        message (str): Raw SMS text string.
        
    Returns:
        dict: {
            "message": str,
            "prediction": "SPAM" | "NOT SPAM",
            "is_spam": bool,
            "confidence": float (percentage, e.g. 98.4),
            "probabilities": {"SPAM": float, "NOT SPAM": float}
        }
    """
    if not isinstance(message, str) or not message.strip():
        raise ValueError("SMS message must be a non-empty string.")
        
    pipe = get_pipeline()
    raw_text = message.strip()
    
    # Predict label using the end-to-end pipeline
    prediction = str(pipe.predict([raw_text])[0])
    is_spam = (prediction == "SPAM")
    
    probabilities = {}
    confidence = 100.0
    
    if hasattr(pipe, "predict_proba"):
        probs = pipe.predict_proba([raw_text])[0]
        classes = list(pipe.classes_)
        for cls_name, p in zip(classes, probs):
            probabilities[str(cls_name)] = round(float(p) * 100, 2)
        confidence = probabilities.get(prediction, 100.0)
    elif hasattr(pipe, "decision_function"):
        score = pipe.decision_function([raw_text])[0]
        confidence = round(float(abs(score)), 2)
        
    return {
        "message": raw_text,
        "prediction": prediction,
        "is_spam": is_spam,
        "confidence": confidence,
        "probabilities": probabilities
    }

if __name__ == "__main__":
    # Quick CLI self-test
    sample = "Congratulations! You have WON ₹50,000 in lucky draw. Click http://bit.ly/prize to claim!"
    result = predict_sms(sample)
    print("Inference Test Result:")
    print(result)
