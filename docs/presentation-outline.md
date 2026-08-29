# Academic Presentation Slide Deck Outline

This document provides the structured slide-by-slide outline and speaker talking points for presenting the **Spam SMS Filtering System (SMS SENTINEL)** to academic review boards and evaluators.

---

### Slide 1: Title & Team
- **Title**: SMS SENTINEL — AI-Powered Spam SMS Threat Detection & Intelligence Platform
- **Sub-Title**: A Dual-Engine Machine Learning & Deterministic Forensics Framework for Mobile Messaging Security
- **Team**: Final Year Engineering Project / Capstone Evaluation
- **Tech Stack**: Python | Flask | Scikit-learn | SQLite | Vanilla JS | Chart.js

---

### Slide 2: Problem Statement
- Proliferation of SMS spam, phishing (smishing), banking scams, and lottery fraud.
- Vulnerability of end-users due to high trust in mobile text messaging.
- Limitations of manual filtering and static keyword blocklists.

---

### Slide 3: Motivation
- Over 90% of text messages are opened within 3 minutes of receipt.
- Severe financial losses resulting from credential harvesting and fake KYC updates.
- Need for a lightweight, transparent, and explainable client-side threat detection engine.

---

### Slide 4: Project Objectives
- Build an end-to-end web-based threat triage console for SMS text analysis.
- Train and deploy a high-precision ML text classification pipeline.
- Implement a secondary deterministic heuristic engine (Message X-Ray).
- Provide a persistent SQLite audit archive with search, filtering, and real-time analytics.

---

### Slide 5: Existing Systems vs. Limitations
- **Existing Keyword Blocklists**: High false alarm rate, easily bypassed by homoglyphs and leetspeak.
- **Pure Statistical ML**: Lacks structural awareness (e.g., cannot distinguish verified bank domains from shortened phishing links).
- **Cloud-Only APIs**: High latency, privacy concerns with sensitive personal SMS contents.

---

### Slide 6: Proposed Dual-Engine Architecture
- **Stage 1**: NLP TF-IDF Feature Extraction + Multinomial Naive Bayes Classification.
- **Stage 2**: Message X-Ray Deterministic Heuristic Engine (Threat Scoring & Token Flagging).
- **Stage 3**: Defense Protocol Generator (Tailored mitigation instructions).
- **Stage 4**: SQLite Telemetry & Real-Time Aggregation Layer.

---

### Slide 7: System Architecture & Data Flow
- Visual diagram showing Presentation Layer (HTML5/CSS3/Vanilla JS), Application Layer (Flask REST API), Intelligence Layer (ML Pipeline + X-Ray Heuristics), and Data Layer (SQLite `spamshield.db`).
- Review of DFD Level 0 and Level 1 flows.

---

### Slide 8: Machine Learning Methodology
- **Dataset**: UCI SMS Spam Collection + Modern Verified Banking/Smishing Samples (5,189 unique records).
- **Feature Extraction**: Sublinear TF-IDF with $(1, 2)$ $N$-grams (5,000 max features).
- **Classifier Selection**: Benchmark against Logistic Regression and Linear SVM; selection of Multinomial Naive Bayes ($\alpha = 0.1$).

---

### Slide 9: Experimental Results & Model Evaluation
- **Accuracy**: 98.55%
- **Precision**: 97.56% (Only 3 false positives out of 906 legitimate test messages)
- **Recall**: 90.91%
- **F1-Score**: 94.12%
- **Inference Latency**: $< 10\text{ms}$ per message.

---

### Slide 10: User Interface & Experience Design
- Cyber-defense dark aesthetic with high-contrast emerald/amber/red indicators.
- Live status telemetry dot and interactive demo scenario pills.
- Zero external frontend frameworks (Pure vanilla JS for sub-millisecond responsiveness).
- Light/Dark theme toggle and full mobile viewport responsiveness.

---

### Slide 11: Message X-Ray & Forensic Intelligence
- Token-level threat attribution highlighting exact malicious phrases.
- Multi-dimensional message statistics (character count, uppercase ratio, link count).
- Actionable defense protocols (e.g., "Delete immediately, block sender").

---

### Slide 12: Audit Archive & Investigation Detail
- Persistent storage of every analysis in SQLite.
- Instant keyword search with debouncing.
- Multi-criteria filtering by prediction verdict and risk level.
- Interactive investigation drawer displaying complete saved telemetry without re-running ML.

---

### Slide 13: Real-Time Insights & Analytics
- Live dashboard driven by SQL aggregation queries (`SUM`, `COUNT`, `AVG`).
- Detection Activity Timeline and Threat Severity Distribution charts via Chart.js.
- Frequency ranking of most common risk indicators across all historical records.

---

### Slide 14: Testing & Security Hardening
- 42/42 automated test cases passing in Python `unittest`.
- Input boundaries (1,000 char limits, 16KB payload caps).
- Full XSS script injection neutralization via safe text DOM nodes.
- Parameterized SQL queries preventing SQL injection.

---

### Slide 15: Limitations & Future Scope
- **Limitations**: English-language focus, local standalone deployment, static training dataset.
- **Future Scope**: Multilingual NLP (Indic languages), SMS screenshot OCR, mobile OS native integration, carrier-level SMPP gateway proxies.

---

### Slide 16: Conclusion & Viva Demonstration
- Summary of project achievements: High-accuracy, low-latency, explainable SMS cyber-defense.
- Live Demonstration: Real-time scan, archive audit, and insights dashboard.
- Open for Questions & Evaluation.
