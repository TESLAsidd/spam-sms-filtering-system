# Project Abstract: Spam SMS Filtering & Threat Detection System

**Project Title:** Spam SMS Filtering System (SMS Sentinel)  
**Domain:** Artificial Intelligence, Natural Language Processing (NLP), Cybersecurity, Full-Stack Web Engineering  
**Technology Stack:** Python, Flask, Scikit-learn, TF-IDF Vectorization, Multinomial Naive Bayes, SQLite, HTML5, Vanilla CSS3, JavaScript (ES6+), Chart.js  

---

### Abstract

Short Message Service (SMS) remains one of the most widely utilized personal and transactional communication channels worldwide. However, its ubiquitous reach and high open rates make it a prime target for cybercriminals deploying unsolicited commercial advertisements, smishing (SMS phishing), banking impersonation fraud, and credential-harvesting schemes. Traditional rule-based keyword filters and static blocklists often fail to adapt to adversarial evasion techniques, homoglyphs, and evolving social engineering tactics.

This project presents **SMS SENTINEL**, an end-to-end, full-stack intelligent Spam SMS Detection and Threat Intelligence platform. The system implements a dual-engine architecture combining a machine learning text classification pipeline with a deterministic heuristic risk engine (Message X-Ray). The text classification engine leverages term frequency-inverse document frequency (TF-IDF) feature extraction with sublinear scaling and word/character $N$-gram representations ($N \in \{1, 2\}$) coupled with a calibrated **Multinomial Naive Bayes (MNB)** classifier trained on verified SMS spam corpora. The secondary heuristic analyzer independently extracts domain-specific indicators, including high-risk URLs, phone numbers, urgency triggers, monetary keywords, and promotional calls-to-action, mapping them onto a normalized 0–100 Threat Score.

The application is deployed as a modular Flask RESTful API and a lightweight, zero-dependency responsive cybersecurity web console. Classified SMS messages, threat scores, risk signals, and forensic tokens are persisted in an embedded SQLite database, supporting full-text search, multi-criteria risk filtering, paginated investigation inspection, and real-time telemetry aggregations. On a holdout test dataset of 1,038 unique SMS messages, the classification engine achieved an **accuracy of 98.55%**, **precision of 97.56%**, **recall of 90.91%**, and an **F1-score of 94.12%**. The resulting system provides individuals and organizations with an explainable, low-latency, and highly resilient defense mechanism against mobile text-based fraud.
