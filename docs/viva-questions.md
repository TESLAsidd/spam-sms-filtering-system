# Academic Viva Voce & Technical Defense Questions

This document provides concise, technically rigorous answers for project viva examinations, technical interviews, and academic project defenses for the **Spam SMS Filtering System (SMS SENTINEL)**.

---

### 1. What is the project?
**Answer:** The Spam SMS Filtering System (SMS Sentinel) is an AI-powered, full-stack cybersecurity web application that detects, classifies, and analyzes malicious and unsolicited SMS text messages in real time. It utilizes a trained Scikit-learn Machine Learning pipeline (TF-IDF + Multinomial Naive Bayes) combined with a deterministic heuristic threat engine (Message X-Ray) and an embedded SQLite database for audit logging and real-time intelligence telemetry.

---

### 2. Why did you choose SMS spam detection?
**Answer:** SMS is a ubiquitous communication channel with open rates exceeding 90%, making it a prime vector for smishing (SMS phishing), financial fraud, and account takeover attacks. Unlike email, mobile SMS lacks centralized SPF/DKIM authentication and deep content filtering at the handset level, creating an urgent need for intelligent, low-latency, and explainable mobile threat detection.

---

### 3. What is Natural Language Processing (NLP)?
**Answer:** Natural Language Processing (NLP) is a subfield of artificial intelligence and computational linguistics that enables computers to understand, interpret, and manipulate human language. In this project, NLP techniques—including tokenization, stop-word removal, sublinear frequency scaling, and $N$-gram feature extraction—are used to transform unstructured SMS text into structured mathematical vectors for machine learning classification.

---

### 4. Why use TF-IDF (Term Frequency-Inverse Document Frequency)?
**Answer:** Raw word counts (Bag-of-Words) bias models toward high-frequency words that appear everywhere. TF-IDF balances the local frequency of a word in a specific message ($\text{TF}$) against its global rarity across the entire corpus ($\text{IDF}$). This gives high mathematical weight to discriminative spam keywords (like `claim`, `urgent`, `prize`, `suspended`) while diminishing the importance of common conversational terms.

---

### 5. What is the selected ML classifier?
**Answer:** The selected classifier is **Multinomial Naive Bayes (MNB)** with Laplace smoothing ($\alpha = 0.1$).

---

### 6. Why was Multinomial Naive Bayes selected over candidate models?
**Answer:** In empirical benchmark testing against Logistic Regression and Linear Support Vector Machines (SVM), Multinomial Naive Bayes achieved the highest overall **Accuracy (98.55%)** and **F1-Score (94.12%)** with exceptional **Precision (97.56%)** producing only 3 False Positives out of 906 legitimate test messages. Furthermore, MNB requires simple logarithmic additions during inference, executing in under 10ms with a compact 400KB serialized model size.

---

### 7. What is training data?
**Answer:** Training data is the historical, labeled subset of the dataset (80% / 4,151 samples in our project) used by the learning algorithm to calculate prior class probabilities $P(y)$ and feature conditional likelihoods $P(x_i \mid y)$ for each N-gram token.

---

### 8. What is testing data?
**Answer:** Testing data is an independent, holdout subset of data (20% / 1,038 samples in our project) that the model never saw during training. It is used to objectively evaluate the model's generalization capabilities on unseen messages.

---

### 9. What is overfitting, and how is it prevented?
**Answer:** Overfitting occurs when a machine learning model memorizes noise and specific idiosyncrasies of the training data, resulting in high training accuracy but poor performance on unseen test data. In our project, overfitting is prevented by:
1. Removing duplicate messages before train/test splitting to prevent data leakage.
2. Limiting the TF-IDF feature space to the top 5,000 informative N-grams.
3. Applying Laplace smoothing ($\alpha = 0.1$) to prevent zero-probability traps for unseen vocabulary words.

---

### 10. What is Precision?
**Answer:** Precision measures the proportion of predicted spam messages that were genuinely spam:
$$\text{Precision} = \frac{\text{True Positives (TP)}}{\text{True Positives (TP)} + \text{False Positives (FP)}} = \frac{120}{120 + 3} = 97.56\%$$
High precision ensures the system rarely misclassifies legitimate messages as spam.

---

### 11. What is Recall?
**Answer:** Recall (Sensitivity) measures the proportion of actual spam messages in the dataset that were correctly identified:
$$\text{Recall} = \frac{\text{True Positives (TP)}}{\text{True Positives (TP)} + \text{False Negatives (FN)}} = \frac{120}{120 + 12} = 90.91\%$$

---

### 12. What is F1-Score?
**Answer:** The F1-Score is the harmonic mean of Precision and Recall, providing a single balanced metric that penalizes extreme imbalances:
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 2 \times \frac{0.9756 \times 0.9091}{0.9756 + 0.9091} = 94.12\%$$

---

### 13. Why is Accuracy alone insufficient for spam filtering?
**Answer:** The SMS dataset is naturally imbalanced (~87% legitimate, ~13% spam). A naive dummy model that classifies every message as `NOT SPAM` would achieve an 87% accuracy while catching 0% of spam. Therefore, Precision, Recall, and F1-score are necessary to evaluate true detection efficacy.

---

### 14. What does the Flask backend do?
**Answer:** The Flask backend acts as the RESTful application layer:
- Ingests and sanitizes incoming HTTP JSON payloads with strict length limits (1,000 chars) and 16KB max payload checks.
- Manages the in-memory singleton ML pipeline to perform sub-millisecond inference.
- Executes the secondary deterministic Message X-Ray analysis.
- Handles database transactions (CRUD operations, parameterized queries, and SQL telemetry aggregations).
- Serves HTTP security headers (`X-Frame-Options`, `X-Content-Type-Options`).

---

### 15. Why use SQLite?
**Answer:** SQLite is a serverless, zero-configuration, ACID-compliant relational database engine embedded directly into the Python runtime. It provides persistent storage without requiring external database servers or complex network connections, making it optimal for lightweight, standalone cybersecurity appliances.

---

### 16. How does the frontend communicate with Flask?
**Answer:** The frontend uses the native asynchronous JavaScript `fetch()` API to make non-blocking HTTP requests (`POST /api/predict`, `GET /api/analyses`, `GET /api/insights`, `DELETE /api/analyses/<id>`) sending and receiving structured JSON payloads.

---

### 17. How are risk indicators generated?
**Answer:** Risk indicators are generated by the **Message X-Ray** deterministic rule engine using compiled regular expressions and pattern extractors. It identifies high-risk features (suspicious URLs, phone numbers, urgency language, currency keywords, fake lottery claims, and call-to-action triggers) independently of ML probabilistic weights.

---

### 18. Is Threat Score the same as Model Confidence?
**Answer:** **No.** Model Confidence is the statistical probability ($0.0\%\text{–}100.0\%$) generated by the Naive Bayes classifier that a message belongs to the predicted class based on TF-IDF word distributions. Threat Score is a separate heuristic severity index ($0\text{–}100$) reflecting structural risk factors (e.g., presence of unverified web links, urgency, financial keywords). A message might have moderate ML confidence but a high Threat Score if it contains explicit phishing links.

---

### 19. What are False Positives, and what is their impact?
**Answer:** A False Positive occurs when a legitimate SMS is incorrectly classified as `SPAM`. In messaging systems, this is highly disruptive because users may miss critical banking OTPs, appointment reminders, or urgent personal messages. Our system minimizes false positives (Precision: 97.56%) through conservative prior tuning and sublinear TF scaling.

---

### 20. What are False Negatives, and how does the system mitigate them?
**Answer:** A False Negative occurs when a malicious spam message is incorrectly classified as `NOT SPAM`. Our dual-engine architecture mitigates false negatives because even if an adversarial phrase evades the statistical ML model, the secondary Message X-Ray flags high-risk URLs and urgency tokens, alerting the user via the Threat Score and defensive action protocol.

---

### 21. What are the current limitations of the system?
**Answer:**
1. **Language Scope**: Currently optimized for English-language SMS text.
2. **Offline Corpus**: Training is based on static datasets; emerging zero-day scams require periodic retraining.
3. **Standalone Architecture**: Operates as a local web application rather than an integrated handset OS SMS interceptor daemon.

---

### 22. What can be improved in future iterations?
**Answer:**
1. **Multilingual NLP**: Support for Indic and international languages using multilingual transformers (mBERT / XLM-RoBERTa).
2. **Optical Character Recognition (OCR)**: Ability to upload and parse SMS screenshots directly.
3. **Active Learning Feedback**: Allow analysts to flag misclassifications to automatically update training datasets.
4. **Cloud & Carrier Gateway Integration**: Deploy as an upstream SMPP/HTTP webhook proxy for cellular network carriers.
