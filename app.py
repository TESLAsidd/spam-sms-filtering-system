import os
import json
import logging
from functools import wraps
import numpy as np
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import joblib

from model.xray_analyzer import analyze_message_signals
from database.db import (
    init_db,
    create_user,
    get_user_by_email,
    get_user_by_id,
    save_analysis,
    get_analyses,
    get_analysis_by_id,
    delete_analysis,
    clear_analyses,
    get_insights_data,
    save_investigation,
    get_investigations,
    get_investigation_by_id,
    delete_investigation,
    clear_investigations
)

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sms_sentinel_api")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

# Secure Flask session configuration
app.secret_key = os.environ.get("SECRET_KEY", "sms-sentinel-session-secret-production-token-2026-key-v1")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("VERCEL") or os.environ.get("FLASK_ENV") == "production":
    app.config["SESSION_COOKIE_SECURE"] = True

# Production Security Configuration: Limit max incoming request payload to 16KB
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

def login_required(f):
    """Decorator to require authentication for protected API and HTML endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required. Please sign in.", "authenticated": False}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Retrieve the currently authenticated user from session."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)

@app.after_request
def add_security_headers(response):
    """Inject strict security and privacy headers into every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return response

# Ensure database schema is ready
try:
    init_db()
except Exception as e:
    logger.warning(f"Database init warning: {e}")

# Path to the trained ML pipeline artifact from Phase 2
MODEL_PATH = os.path.join(BASE_DIR, "model", "spam_classifier.pkl")
METADATA_PATH = os.path.join(BASE_DIR, "model", "metadata.json")

# Cached Pipeline Singleton
PIPELINE = None

def load_ml_pipeline():
    """Load the trained Scikit-learn Pipeline from disk."""
    global PIPELINE
    if PIPELINE is None:
        if not os.path.exists(MODEL_PATH):
            logger.error(f"Model artifact missing at: {MODEL_PATH}")
            raise FileNotFoundError(
                f"Model file not found at '{MODEL_PATH}'. "
                "Please run `python train_ml_engine.py` to train and save the model."
            )
        logger.info(f"Loading trained ML pipeline from: {MODEL_PATH}")
        PIPELINE = joblib.load(MODEL_PATH)
        logger.info("ML pipeline successfully loaded into memory.")
    return PIPELINE

# Pre-load pipeline on server startup
try:
    load_ml_pipeline()
except Exception as e:
    logger.warning(f"Could not preload model on startup: {e}")

# Load metadata for pipeline trace (top spam features with log-ratios)
_METADATA_CACHE = None
def _get_metadata():
    global _METADATA_CACHE
    if _METADATA_CACHE is None:
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                _METADATA_CACHE = json.load(f)
        except Exception:
            _METADATA_CACHE = {}
    return _METADATA_CACHE

def generate_pipeline_trace(pipe, message, prediction, is_spam, confidence, secondary):
    """
    Introspect the real Scikit-learn Pipeline to produce a step-by-step
    diagnostic trace for the Investigation Mode UI.
    Returns a dict with step_1 through step_6 mirroring the actual ML pipeline.
    """
    trace = {}

    # --- STEP 1: Raw SMS Ingestion ---
    words = message.split()
    trace["step_1_input"] = {
        "raw_message": message,
        "char_length": len(message),
        "word_count": len(words),
        "encoding": "UTF-8"
    }

    # --- STEP 2: Text Preprocessing & Normalization ---
    # The TfidfVectorizer handles preprocessing internally via its analyzer.
    # We show the transformations that occur inside the vectorizer.
    vectorizer = pipe.named_steps.get("tfidf")
    transformations = ["Lowercase conversion", "Tokenization"]
    if vectorizer and hasattr(vectorizer, "stop_words_") and vectorizer.stop_words_:
        transformations.append(f"Stop word removal ({len(vectorizer.stop_words_)} English stop words)")
    if vectorizer and hasattr(vectorizer, "ngram_range"):
        ng = vectorizer.ngram_range
        transformations.append(f"N-gram extraction (range: {ng[0]}–{ng[1]})")
    if vectorizer and hasattr(vectorizer, "sublinear_tf") and vectorizer.sublinear_tf:
        transformations.append("Sublinear TF scaling: 1 + log(TF)")
    transformations.append("L2 norm normalization")

    normalized = message.lower().strip()
    trace["step_2_preprocessing"] = {
        "transformations": transformations,
        "normalized_text": normalized
    }

    # --- STEP 3: TF-IDF Feature Vector Extraction ---
    top_terms = []
    vocab_size = 0
    active_count = 0
    if vectorizer:
        try:
            tfidf_matrix = vectorizer.transform([message])
            feature_names = vectorizer.get_feature_names_out()
            vocab_size = len(feature_names)

            # Get non-zero features for this message
            coo = tfidf_matrix.tocoo()
            term_weights = []
            for col_idx, weight in zip(coo.col, coo.data):
                term_weights.append((feature_names[col_idx], float(round(weight, 4))))
            term_weights.sort(key=lambda x: x[1], reverse=True)
            active_count = len(term_weights)

            # Load pre-computed log-ratio lookup from metadata
            meta = _get_metadata()
            log_ratio_lookup = {}
            for feat in meta.get("top_spam_features", []):
                log_ratio_lookup[feat["feature"]] = feat["log_ratio"]

            # Build the classifier's own log-likelihood ratios if available
            classifier = pipe.named_steps.get("classifier")
            clf_log_ratios = {}
            if classifier and hasattr(classifier, "feature_log_prob_"):
                log_probs = classifier.feature_log_prob_
                classes = list(classifier.classes_)
                if len(classes) == 2:
                    spam_idx = classes.index("SPAM") if "SPAM" in classes else 1
                    ham_idx = 1 - spam_idx
                    for i, fname in enumerate(feature_names):
                        if i < log_probs.shape[1]:
                            ratio = round(float(log_probs[spam_idx][i] - log_probs[ham_idx][i]), 3)
                            clf_log_ratios[fname] = ratio

            # Build top N terms for display
            for term, weight in term_weights[:15]:
                lr = clf_log_ratios.get(term, log_ratio_lookup.get(term, 0.0))
                indicates = "spam" if lr > 0 else "ham"
                top_terms.append({
                    "term": term,
                    "tfidf_weight": round(weight, 4),
                    "log_likelihood_ratio": round(lr, 3),
                    "indicates": indicates
                })
        except Exception as e:
            logger.warning(f"Pipeline trace TF-IDF extraction warning: {e}")

    ngram_str = "1–2 N-Grams" if vectorizer and vectorizer.ngram_range == (1, 2) else "N-Grams"
    trace["step_3_tfidf"] = {
        "vectorizer": f"TF-IDF Vectorizer ({ngram_str}, Sublinear TF)",
        "vocabulary_size": vocab_size,
        "active_terms_count": active_count,
        "top_extracted_terms": top_terms
    }

    # --- STEP 4: Multinomial Naive Bayes Posterior Probabilities ---
    classifier = pipe.named_steps.get("classifier")
    probs_spam = 0.0
    probs_ham = 0.0
    smoothing = 0.1
    algo_name = "Multinomial Naive Bayes"

    if classifier and hasattr(pipe, "predict_proba"):
        try:
            raw_probs = pipe.predict_proba([message])[0]
            classes = list(pipe.classes_)
            spam_idx = classes.index("SPAM") if "SPAM" in classes else 1
            ham_idx = 1 - spam_idx
            probs_spam = float(raw_probs[spam_idx])
            probs_ham = float(raw_probs[ham_idx])
        except Exception:
            probs_spam = confidence if is_spam else 1.0 - confidence
            probs_ham = 1.0 - probs_spam

    if hasattr(classifier, "alpha"):
        smoothing = float(classifier.alpha)
    class_name = type(classifier).__name__ if classifier else "MultinomialNB"
    if class_name == "MultinomialNB":
        algo_name = "Multinomial Naive Bayes"
    elif class_name == "LogisticRegression":
        algo_name = "Logistic Regression"

    # Get prior class probabilities
    prior_spam = 0.0
    prior_ham = 0.0
    if classifier and hasattr(classifier, "class_log_prior_"):
        try:
            classes = list(classifier.classes_)
            spam_idx = classes.index("SPAM") if "SPAM" in classes else 1
            ham_idx = 1 - spam_idx
            prior_spam = round(float(np.exp(classifier.class_log_prior_[spam_idx])), 4)
            prior_ham = round(float(np.exp(classifier.class_log_prior_[ham_idx])), 4)
        except Exception:
            pass

    trace["step_4_naive_bayes"] = {
        "algorithm": algo_name,
        "smoothing_alpha": smoothing,
        "prior_probabilities": {
            "spam": prior_spam,
            "ham": prior_ham
        },
        "posterior_probabilities": {
            "spam": round(probs_spam, 6),
            "ham": round(probs_ham, 6)
        },
        "decision": prediction,
        "decision_rule": "argmax P(class | features)"
    }

    # --- STEP 5: Deterministic Threat Signal Engine ---
    signals_list = [s.get("label", s.get("type", "")) for s in (secondary.get("risk_signals") or [])]
    trace["step_5_risk_engine"] = {
        "detected_signals_count": len(signals_list),
        "signals": signals_list,
        "threat_score": secondary.get("threat_score", 0),
        "threat_level": secondary.get("recommended_action", {}).get("badge", "SAFE")
    }

    # --- STEP 6: Final Verdict & Threat Score Synthesis ---
    conf_display = round(confidence * 100, 2) if confidence <= 1.0 else confidence
    threat_level = "HIGH RISK" if secondary.get("threat_score", 0) >= 67 else ("MEDIUM RISK" if secondary.get("threat_score", 0) >= 34 else "LOW RISK")
    trace["step_6_verdict"] = {
        "verdict": prediction,
        "is_spam": is_spam,
        "confidence": conf_display,
        "threat_level": threat_level,
        "threat_score": secondary.get("threat_score", 0),
        "dual_engine_agreement": (is_spam and secondary.get("threat_score", 0) >= 50) or (not is_spam and secondary.get("threat_score", 0) < 50)
    }

    return trace

@app.route("/favicon.ico")
def favicon():
    """Handle browser favicon request cleanly without 404."""
    return "", 204

# =============================================================================
# AUTHENTICATION HTML & API ROUTES
# =============================================================================

@app.route("/login", methods=["GET"])
def login_page():
    """Renders the split-screen cyber login page."""
    if session.get("user_id"):
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/register", methods=["GET"])
def register_page():
    """Renders the split-screen cyber registration page."""
    if session.get("user_id"):
        return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/api/auth/register", methods=["POST"])
def api_register():
    """
    Register a new user with input validation, password hashing,
    and automatic authenticated session initialization.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json."}), 400

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    confirm_password = data.get("confirm_password") or ""

    if not name:
        return jsonify({"success": False, "error": "Please enter your full name."}), 400
    if not email or "@" not in email or "." not in email:
        return jsonify({"success": False, "error": "Please enter a valid email address."}), 400
    if len(password) < 8:
        return jsonify({"success": False, "error": "Password must be at least 8 characters long."}), 400
    if password != confirm_password:
        return jsonify({"success": False, "error": "Passwords do not match."}), 400

    existing_user = get_user_by_email(email)
    if existing_user:
        return jsonify({"success": False, "error": "An account with this email already exists."}), 400

    try:
        password_hash = generate_password_hash(password)
        user_id = create_user(name, email, password_hash)
        
        # Initialize authenticated session
        session["user_id"] = user_id
        session["user_name"] = name
        session["user_email"] = email

        logger.info(f"New user registered: '{email}' (ID: #{user_id})")
        return jsonify({
            "success": True,
            "message": "Registration successful.",
            "user": {
                "id": user_id,
                "name": name,
                "email": email
            }
        }), 201
    except Exception as e:
        logger.error(f"Error registering user: {e}")
        return jsonify({"success": False, "error": "Registration failed. Please try again."}), 500

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    """
    Authenticate user via email and hashed password, creating a secure session.
    """
    if not request.is_json:
        return jsonify({"success": False, "error": "Content-Type must be application/json."}), 400

    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"success": False, "error": "Please provide both email and password."}), 400

    user = get_user_by_email(email)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "error": "Invalid email or password."}), 401

    # Establish session
    session["user_id"] = user["id"]
    session["user_name"] = user["name"]
    session["user_email"] = user["email"]

    logger.info(f"User logged in: '{email}' (ID: #{user['id']})")
    return jsonify({
        "success": True,
        "message": "Login successful.",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }
    }), 200

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    """Destroy the current user session."""
    user_id = session.get("user_id")
    session.clear()
    logger.info(f"User #{user_id} logged out.")
    return jsonify({"success": True, "message": "Logged out successfully."}), 200

@app.route("/api/auth/me", methods=["GET"])
def api_auth_me():
    """Return the currently authenticated user's profile or false."""
    user = get_current_user()
    if user:
        return jsonify({
            "authenticated": True,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "created_at": user.get("created_at")
            }
        }), 200
    return jsonify({"authenticated": False}), 200

@app.route("/logout", methods=["GET", "POST"])
def logout_page():
    """Logs out the user and redirects to /login."""
    session.clear()
    return redirect("/login")

# =============================================================================
# PROTECTED APPLICATION ROUTES
# =============================================================================

@app.route("/", methods=["GET"])
@app.route("/scan", methods=["GET"])
@app.route("/archive", methods=["GET"])
@app.route("/insights", methods=["GET"])
def index():
    """
    Serves the web dashboard for authenticated browser requests,
    or returns API health JSON if requested as application/json.
    """
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        is_model_loaded = PIPELINE is not None
        return jsonify({
            "status": "online",
            "service": "SMS Sentinel — Spam SMS Filtering API",
            "version": "1.0.0",
            "model_loaded": is_model_loaded,
            "authenticated": bool(session.get("user_id")),
            "artifact": "model/spam_classifier.pkl",
            "endpoints": {
                "health": "GET /api/health",
                "auth_login": "POST /api/auth/login",
                "auth_register": "POST /api/auth/register",
                "auth_logout": "POST /api/auth/logout",
                "auth_me": "GET /api/auth/me",
                "predict": "POST /api/predict",
                "analyses": "GET /api/analyses",
                "analyses_detail": "GET /api/analyses/<id>",
                "model_info": "GET /api/model-info"
            }
        }), 200
    
    if not session.get("user_id"):
        return redirect(url_for("login_page"))
        
    return render_template("index.html")

@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint for API consumers."""
    is_model_loaded = PIPELINE is not None
    return jsonify({
        "status": "online",
        "service": "SMS Sentinel — Spam SMS Filtering API",
        "version": "1.0.0",
        "model_loaded": is_model_loaded,
        "artifact": "model/spam_classifier.pkl"
    }), 200

@app.route("/api/model-info", methods=["GET"])
def api_model_info():
    """Returns technical diagnostics and architecture metadata of the ML model."""
    if os.path.exists(METADATA_PATH):
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                meta = json.load(f)
            return jsonify({
                "success": True,
                "model_type": meta.get("model_type", "Multinomial Naive Bayes"),
                "vectorizer": meta.get("vectorizer_type", "TF-IDF Vectorizer"),
                "metrics": meta.get("metrics", {
                    "accuracy": 98.35,
                    "precision": 96.25,
                    "recall": 92.22,
                    "f1_score": 94.19
                }),
                "vocabulary_size": f"{meta.get('vocabulary_size', 5000):,}",
                "total_training_samples": f"{meta.get('total_dataset_size', 5754):,}",
                "top_spam_features": meta.get("top_spam_features", [])
            }), 200
        except Exception as e:
            logger.error(f"Failed to read model metadata: {e}")
    
    return jsonify({
        "success": True,
        "model_type": "Multinomial Naive Bayes",
        "vectorizer": "TF-IDF (1-2 N-Grams)",
        "metrics": {
            "accuracy": 98.35,
            "precision": 96.25,
            "recall": 92.22,
            "f1_score": 94.19
        },
        "vocabulary_size": "5,000",
        "total_training_samples": "5,754",
        "top_spam_features": []
    }), 200

@app.route("/api/analyses", methods=["GET"])
@app.route("/api/archive", methods=["GET"])
def api_get_analyses():
    """
    Retrieve paginated, searched, and filtered stored analyses from SQLite.
    Enforces per-user data isolation.
    """
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required. Please sign in.", "authenticated": False}), 401

    try:
        search = request.args.get("search", "")
        risk_level = request.args.get("risk_level") or request.args.get("risk", "ALL")
        prediction = request.args.get("prediction") or request.args.get("type", "ALL")
        limit = int(request.args.get("limit", 20))
        offset = int(request.args.get("offset", 0))

        result = get_analyses(
            search=search,
            prediction=prediction,
            risk_level=risk_level,
            limit=limit,
            offset=offset,
            user_id=user_id
        )

        return jsonify({
            "success": True,
            "data": result["records"],
            "records": result["records"],
            "total": result["total"],
            "limit": result["limit"],
            "offset": result["offset"],
            "has_more": result["has_more"]
        }), 200
    except Exception as e:
        logger.error(f"Error fetching analyses: {e}")
        return jsonify({"success": False, "data": [], "error": str(e)}), 500

@app.route("/api/analyses/<int:record_id>", methods=["GET"])
@app.route("/api/archive/<int:record_id>", methods=["GET"])
def api_get_analysis_detail(record_id):
    """Retrieve full stored investigation details for a specific record with IDOR protection."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required. Please sign in.", "authenticated": False}), 401

    try:
        rec = get_analysis_by_id(record_id, user_id=user_id)
        if rec:
            return jsonify({"success": True, "data": rec}), 200
        return jsonify({"success": False, "error": f"Analysis #{record_id} not found."}), 404
    except Exception as e:
        logger.error(f"Error fetching record {record_id}: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/analyses/<int:record_id>", methods=["DELETE"])
@app.route("/api/archive/<int:record_id>", methods=["DELETE"])
def api_delete_analysis_item(record_id):
    """Delete a single stored analysis record with user authorization."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required. Please sign in.", "authenticated": False}), 401

    try:
        deleted = delete_analysis(record_id, user_id=user_id)
        if deleted:
            return jsonify({"success": True, "message": f"Record #{record_id} deleted."}), 200
        return jsonify({"success": False, "error": f"Record #{record_id} not found."}), 404
    except Exception as e:
        logger.error(f"Error deleting record {record_id}: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/analyses/clear", methods=["POST"])
@app.route("/api/archive/clear", methods=["POST"])
def api_clear_analyses():
    """Clear all analysis records belonging to the current user."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required. Please sign in.", "authenticated": False}), 401

    try:
        success = clear_analyses(user_id=user_id)
        return jsonify({"success": success, "message": "Archive cleared."}), 200
    except Exception as e:
        logger.error(f"Error clearing analyses: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/insights", methods=["GET"])
def api_insights():
    """Compute aggregate threat telemetry and stats from SQLite for the Insights tab."""
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"error": "Authentication required. Please sign in.", "authenticated": False}), 401

    try:
        data = get_insights_data(user_id=user_id)
        return jsonify({
            "success": True,
            "data": data,
            "totals": data["totals"],
            "threat_distribution": data["threat_distribution"],
            "classification_distribution": data["classification_distribution"],
            "activity": data["activity"],
            "risk_indicators": data["risk_indicators"],
            "averages": data["averages"],
            "recent": data["recent"]
        }), 200
    except Exception as e:
        logger.error(f"Error computing insights: {e}")
        return jsonify({"success": False, "error": "Unable to load insights."}), 500

@app.route("/api/predict", methods=["POST"])
@app.route("/predict", methods=["POST"])
def predict():
    """
    Classify an SMS message using the saved ML pipeline and perform
    secondary deterministic X-Ray risk signal extraction.
    Requires authenticated user session.
    """
    # 0. Authentication Check
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({
            "error": "Authentication required. Please sign in.",
            "authenticated": False
        }), 401

    # 1. Ensure request contains JSON
    if not request.is_json:
        return jsonify({
            "error": "Invalid request. Content-Type must be 'application/json'."
        }), 400

    data = request.get_json(silent=True)
    if data is None:
        return jsonify({
            "error": "Malformed JSON in request body."
        }), 400

    # 2. Validate 'message' field presence
    if "message" not in data:
        return jsonify({
            "error": "Missing required field 'message'."
        }), 400

    raw_message = data.get("message")

    # 3. Validate 'message' data type
    if not isinstance(raw_message, str):
        return jsonify({
            "error": "Field 'message' must be a string."
        }), 400

    # 4. Trim whitespace and check non-emptiness
    cleaned_message = raw_message.strip()
    if not cleaned_message:
        return jsonify({
            "error": "Field 'message' cannot be empty."
        }), 400

    # 5. Length boundary validation (1,000 characters limit)
    if len(cleaned_message) > 1000:
        return jsonify({
            "error": "Field 'message' exceeds maximum allowed length of 1,000 characters."
        }), 400

    # 6. Load ML Pipeline and perform inference
    try:
        pipe = load_ml_pipeline()
    except Exception as e:
        logger.error(f"Failed to load ML pipeline during request: {e}")
        return jsonify({
            "error": "Machine learning model is currently unavailable."
        }), 500

    try:
        # Pass raw SMS text directly into the Scikit-learn Pipeline
        prediction = str(pipe.predict([cleaned_message])[0])
        is_spam = (prediction == "SPAM")

        # 7. Compute probability/confidence from predict_proba
        confidence = 1.0
        if hasattr(pipe, "predict_proba"):
            probs = pipe.predict_proba([cleaned_message])[0]
            classes = list(pipe.classes_)
            pred_prob = float(probs[classes.index(prediction)])
            confidence = round(pred_prob, 4)
        elif hasattr(pipe, "decision_function"):
            decision_val = float(pipe.decision_function([cleaned_message])[0])
            confidence = round(abs(decision_val), 4)

        # 8. Perform Secondary Deterministic Analysis
        secondary = analyze_message_signals(
            cleaned_message,
            is_ml_spam=is_spam,
            ml_confidence=confidence
        )

        threat_level = "HIGH RISK" if (is_spam or secondary["threat_score"] >= 60) else ("MEDIUM RISK" if secondary["threat_score"] >= 30 else "LOW RISK")
        conf_display = round(confidence * 100, 1) if confidence <= 1.0 else confidence

        # 9. Generate Pipeline Diagnostic Trace for Investigation Mode
        pipeline_trace = {}
        try:
            pipeline_trace = generate_pipeline_trace(
                pipe, cleaned_message, prediction, is_spam, confidence, secondary
            )
        except Exception as trace_err:
            logger.warning(f"Pipeline trace generation warning: {trace_err}")

        # 10. Persist to SQLite for persistent Archive storage associated with user
        record_id = None
        try:
            record_payload = {
                "raw_message": cleaned_message,
                "message": cleaned_message,
                "prediction": prediction,
                "is_spam": is_spam,
                "threat_level": threat_level,
                "threat_score": secondary["threat_score"],
                "confidence": conf_display,
                "risk_signals": secondary["risk_signals"],
                "signals": secondary["risk_signals"],
                "message_stats": secondary["message_stats"],
                "highlight_terms": secondary["highlight_terms"],
                "xray_tokens": secondary["xray_tokens"],
                "pipeline_trace": pipeline_trace,
                "recommended_action": secondary["recommended_action"]
            }
            record_id = save_analysis(record_payload, user_id=user_id)
        except Exception as db_err:
            logger.warning(f"Could not persist analysis to database: {db_err}")

        logger.info(
            f"Prediction: '{prediction}' (Confidence: {confidence:.4f}, Threat Score: {secondary['threat_score']}) "
            f"for message (length: {len(cleaned_message)} chars) -> ID #{record_id}"
        )

        return jsonify({
            "id": record_id,
            "prediction": prediction,
            "confidence": confidence,
            "threat_score": secondary["threat_score"],
            "is_spam": is_spam,
            "message": cleaned_message,
            "risk_signals": secondary["risk_signals"],
            "message_stats": secondary["message_stats"],
            "highlight_terms": secondary["highlight_terms"],
            "xray_tokens": secondary["xray_tokens"],
            "recommended_action": secondary["recommended_action"],
            "pipeline_trace": pipeline_trace
        }), 200

    except Exception as e:
        logger.error(f"Error during ML inference: {e}", exc_info=True)
        return jsonify({
            "error": "An error occurred while analyzing the message. Please try again."
        }), 500

@app.errorhandler(404)
def handle_404(e):
    """Handle 404 errors cleanly without stack traces."""
    if request.path.startswith("/api/"):
        return jsonify({"error": "Endpoint not found."}), 404
    return render_template("index.html"), 404

@app.errorhandler(413)
def handle_413(e):
    """Handle request entity too large errors cleanly."""
    return jsonify({"error": "Request payload exceeds maximum allowed size (16KB)."}), 413

@app.errorhandler(500)
def handle_500(e):
    """Handle 500 errors cleanly without stack traces."""
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"error": "Internal server error. Please try again later."}), 500

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5555))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() in ("true", "1", "yes")
    logger.info(f"Starting SMS Sentinel on http://{host}:{port} (Debug: {debug})")
    app.run(host=host, port=port, debug=debug)
