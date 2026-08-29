# System Architecture & Technical Diagrams

This document outlines the architectural blueprints, data flow diagrams, use-case models, procedural flowcharts, and entity-relationship models for the **Spam SMS Filtering System (SMS SENTINEL)**.

---

## 1. High-Level System Architecture

```mermaid
flowchart TD
    subgraph Client["Presentation Tier (Browser)"]
        UI["Web Dashboard (HTML5 / Vanilla CSS3 / ES6 JS)"]
        ScanView["Scan Console"]
        ArchiveView["Archive & Investigation"]
        InsightsView["Real-Time Insights & Charts"]
        UI --> ScanView
        UI --> ArchiveView
        UI --> InsightsView
    end

    subgraph Server["Application Tier (Flask REST API)"]
        Router["HTTP Request Router & Security Layer"]
        PredictEndpoint["POST /api/predict"]
        ArchiveEndpoint["GET/DELETE /api/analyses"]
        InsightsEndpoint["GET /api/insights"]
        Router --> PredictEndpoint
        Router --> ArchiveEndpoint
        Router --> InsightsEndpoint
    end

    subgraph Intelligence["Intelligence Tier (ML & Heuristics)"]
        MLPipeline["Scikit-learn Pipeline (TF-IDF + MultinomialNB)"]
        XRay["Message X-Ray Heuristics Engine"]
        TokenParser["Regex & Pattern Analyzer"]
        XRay --> TokenParser
    end

    subgraph Persistence["Data Tier (SQLite Database)"]
        DB[(spamshield.db)]
        AnalysesTable["analyses Table (Indexed)"]
        DB --- AnalysesTable
    end

    ScanView -- "POST {message}" --> PredictEndpoint
    PredictEndpoint --> MLPipeline
    PredictEndpoint --> XRay
    MLPipeline -- "Prediction & Confidence" --> PredictEndpoint
    XRay -- "Threat Score & Signals" --> PredictEndpoint
    PredictEndpoint -- "Insert Record" --> AnalysesTable
    PredictEndpoint -- "JSON Response" --> ScanView

    ArchiveView -- "GET /api/analyses?filter=..." --> ArchiveEndpoint
    ArchiveEndpoint -- "SELECT Query" --> AnalysesTable
    AnalysesTable -- "Result Rows" --> ArchiveEndpoint
    ArchiveEndpoint -- "JSON Response" --> ArchiveView

    InsightsView -- "GET /api/insights" --> InsightsEndpoint
    InsightsEndpoint -- "SQL Aggregations (SUM/COUNT/AVG)" --> AnalysesTable
    AnalysesTable -- "Aggregated Metrics" --> InsightsEndpoint
    InsightsEndpoint -- "JSON Telemetry" --> InsightsView
```

---

## 2. Data Flow Diagram — DFD Level 0 (Context Level)

```mermaid
flowchart LR
    User([User / Security Analyst])
    System[["Spam SMS Filtering System (SMS Sentinel)"]]
    
    User -- "Raw SMS Text / Query Parameters" --> System
    System -- "Classification, Threat Score, Signals & Insights" --> User
```

---

## 3. Data Flow Diagram — DFD Level 1 (Detailed Subsystems)

```mermaid
flowchart TD
    User([User])
    
    subgraph P1["Process 1.0: Input Validation"]
        P1_Proc["Validate UTF-8 String & Length Limit (1000 Chars)"]
    end

    subgraph P2["Process 2.0: ML Inference"]
        P2_Vec["TF-IDF Vectorization (1-2 N-Grams)"]
        P2_Clf["Multinomial Naive Bayes Classifier"]
        P2_Vec --> P2_Clf
    end

    subgraph P3["Process 3.0: Deterministic Threat X-Ray"]
        P3_Regex["Pattern Matching (URLs, Phones, Urgency, Money)"]
        P3_Score["Compute Threat Score (0-100) & Actions"]
        P3_Regex --> P3_Score
    end

    subgraph P4["Process 4.0: Data Persistence"]
        P4_Save["Store Analysis in SQLite analyses Table"]
    end

    subgraph P5["Process 5.0: Telemetry & Reporting"]
        P5_View["Synthesize Investigation & Dashboard Insights"]
    end

    DB[(SQLite: spamshield.db)]

    User -- "SMS Message" --> P1_Proc
    P1_Proc -- "Clean Text" --> P2_Vec
    P1_Proc -- "Clean Text" --> P3_Regex
    P2_Clf -- "Label & Confidence" --> P4_Save
    P3_Score -- "Threat Signals & Tokens" --> P4_Save
    P4_Save -- "Insert Row" --> DB
    P4_Save -- "Full JSON Response" --> P5_View
    P5_View -- "Rendered Threat UI" --> User

    DB -- "Aggregated Records" --> P5_View
```

---

## 4. UML Use Case Diagram

```mermaid
flowchart LR
    User((User / Analyst))

    subgraph Boundary["SMS Sentinel System"]
        UC1(["Enter SMS Message"])
        UC2(["Analyze Message"])
        UC3(["View ML Prediction & Confidence"])
        UC4(["Inspect Message X-Ray & Signals"])
        UC5(["View Recommended Defense Protocol"])
        UC6(["Browse Audit Archive"])
        UC7(["Search Archive by Keyword"])
        UC8(["Filter Archive by Prediction & Risk"])
        UC9(["Inspect Stored Investigation Record"])
        UC10(["Delete Archive Record"])
        UC11(["View Real-Time System Insights"])
        UC12(["View Detection Charts & Signal Trends"])
    end

    User --> UC1
    User --> UC2
    UC2 --> UC3
    UC2 --> UC4
    UC2 --> UC5
    User --> UC6
    UC6 --> UC7
    UC6 --> UC8
    UC6 --> UC9
    UC6 --> UC10
    User --> UC11
    UC11 --> UC12
```

---

## 5. End-to-End Process Flowchart

```mermaid
flowchart TD
    A([Start]) --> B[User Enters SMS Message]
    B --> C{Is Input Valid?}
    C -- No (Empty / > 1000 Chars) --> D[Return HTTP 400 Bad Request]
    D --> B
    C -- Yes --> E[Clean & Normalize Message]
    
    E --> F[Extract TF-IDF N-Gram Features]
    F --> G[Run Multinomial Naive Bayes Predict Proba]
    G --> H[Determine Prediction: SPAM / NOT SPAM & Confidence]
    
    E --> I[Run Heuristic Pattern Matchers]
    I --> J[Identify Signals: URLs, Phone Numbers, Urgency, Money, Promo, CTA]
    J --> K[Calculate Normalized Threat Score 0-100]
    K --> L[Generate Defensive Recommendation Steps]
    
    H --> M[Consolidate Analysis Payload]
    L --> M
    
    M --> N[Persist Record to SQLite analyses Table]
    N --> O[Return JSON Payload to Frontend]
    O --> P[Render Dual-Verdict Card, X-Ray Tokens & Action Protocol]
    P --> Q([End])
```

---

## 6. Entity-Relationship (ER) Diagram

The system utilizes a clean, single-table normalized SQLite schema optimized for audit logging and low-latency aggregation:

```mermaid
erDiagram
    ANALYSES {
        INTEGER id PK "Auto Increment Primary Key"
        TEXT message "Original raw SMS text content"
        TEXT prediction "SPAM or NOT SPAM classification"
        REAL confidence "Model prediction confidence 0.0000 to 1.0000"
        INTEGER threat_score "Computed Threat Score 0 to 100"
        TEXT threat_level "LOW RISK | MEDIUM RISK | HIGH RISK"
        INTEGER is_spam "Binary flag (1 for Spam, 0 for Legitimate)"
        TEXT risk_signals "JSON serialized list of detected threat signals"
        TEXT message_stats "JSON serialized structural metrics"
        TEXT highlight_terms "JSON serialized risk keyword list"
        TEXT xray_tokens "JSON serialized token classification list"
        TEXT recommended_action "JSON serialized defense steps"
        TEXT pipeline_trace "JSON serialized inference metadata"
        TIMESTAMP created_at "Record timestamp (Default CURRENT_TIMESTAMP)"
    }
```

### Table Index Definitions:
- `idx_analyses_created_at` ON `analyses(created_at DESC)` (Optimizes timeline sorting & activity graphs)
- `idx_analyses_prediction` ON `analyses(prediction)` (Optimizes classification filter queries)
- `idx_analyses_threat_level` ON `analyses(threat_level)` (Optimizes risk severity filter queries)
- `idx_analyses_threat_score` ON `analyses(threat_score)` (Optimizes distribution bucket queries)
