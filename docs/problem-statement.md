# Problem Statement & System Motivation

## 1. Context & Background

Short Message Service (SMS) continues to experience rapid adoption for critical applications, including two-factor authentication (2FA) one-time passwords (OTPs), transactional banking alerts, delivery tracking, and personal communications. Unlike email, which benefits from multi-layered server-side spam filters and domain reputation scoring (SPF/DKIM/DMARC), the cellular SMS infrastructure historically lacks centralized, deep-content security inspection at the end-user terminal.

Because mobile users typically open text messages within 90 seconds of receipt and perceive SMS as a trusted channel, malicious actors exploit this trust to conduct large-scale smishing attacks, financial advance-fee fraud, fake lottery notifications, and impersonation of government and financial institutions.

---

## 2. Challenges of Manual & Rule-Based Filtering

1. **High Cognitive Burden**: Mobile users cannot reliably distinguish sophisticated smishing messages (e.g., urgency-based bank KYC suspension alerts containing obfuscated URLs) from legitimate transactional notices.
2. **Brittle Keyword Filters**: Traditional static keyword lists (e.g., blocking messages containing "WINNER" or "FREE") are easily bypassed by adversaries using zero-width spaces, character substitutions (l33tspeak), and slight lexical rephrasing.
3. **High Cost of False Positives**: In mobile messaging, incorrectly filtering out legitimate communications (e.g., OTPs, bank debit alerts, family messages) causes immediate service disruption.
4. **Lack of Explainability & Intelligence**: Conventional filters present a binary spam/ham label without explaining why a message was flagged or providing actionable mitigation advice to the user.

---

## 3. The Need for Automated Machine Learning Classification

To address these vulnerabilities, modern filtering systems require:
- **Statistical Natural Language Processing (NLP)** to capture contextual co-occurrences of words and sub-word $N$-grams rather than exact keyword matches.
- **Probabilistic Machine Learning Classifiers** capable of generalizing across unseen messages and outputting calibrated confidence scores.
- **Deterministic Heuristic Corroboration** that detects actionable risk vectors (e.g., suspicious URLs, high-urgency keywords, fake lottery claims) independently of classifier probability.
- **Persistent Audit Logging & Telemetry** to enable retrospective investigations and historical threat trend analysis.

---

## 4. Proposed Solution: SMS SENTINEL

**SMS SENTINEL** bridges the gap between machine learning inference and practical cybersecurity triage:
1. Employs a pre-trained **Multinomial Naive Bayes** pipeline with **TF-IDF vectorization** to deliver sub-millisecond, high-accuracy message categorization.
2. Integrates a **Message X-Ray** deterministic heuristics engine that scores structural traits and flags specific threat indicators on a separate 0–100 threat score.
3. Implements an **Embedded SQLite Telemetry & Archive Layer** for persistent audit trails and real-time dashboard analytics.
4. Provides a **Zero-Dependency, Cyber-Defense Web Interface** facilitating safe message inspection, token breakdowns, and clear defensive guidance.
