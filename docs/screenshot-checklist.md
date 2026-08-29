# Project Report Screenshot Catalog & Verification Checklist

This document details the screenshot figures and visual artifacts required for the academic project report, presentation slides, and user manual for the **Spam SMS Filtering System (SMS SENTINEL)**.

---

### Screenshot Catalog Table

| Figure ID | Screen / Component | Description / Capture Scenario | Visual Verification Criteria |
|---|---|---|---|
| **Fig 1.0** | **Scan Page (Initial State)** | Default landing page view on `http://127.0.0.1:5000/` | Shows navigation bar (`SCAN`, `ARCHIVE`, `INSIGHTS`), live status pulse, empty text area, character counter (0/500), and quick demo pills. |
| **Fig 2.0** | **SMS Input State** | User typing or clicking a demo pill | Shows text area populated with SMS content, character counter updating in real-time, and enabled "Analyze Message" button. |
| **Fig 3.0** | **Analysis Loading State** | Transient state during asynchronous API request | "Analyze Message" button enters disabled state with animated spinner and "Analyzing..." label. |
| **Fig 4.0** | **Spam Detection Result** | Output for lottery/prize or banking phishing SMS | Renders bright crimson `SPAM` verdict badge, Model Confidence (e.g., 99.9%), high Threat Score gauge (95/100), and `HIGH RISK` badge. |
| **Fig 5.0** | **Legitimate SMS Result** | Output for conversational or verified transactional message | Renders clean emerald `NOT SPAM` verdict badge, Model Confidence (e.g., 99.5%), minimal Threat Score (4/100), and `LOW RISK` badge. |
| **Fig 6.0** | **Message X-Ray Token Inspector** | Interactive forensic token viewer | Shows individual tokens highlighted with color-coded risk tags (`URL`, `PRIZE`, `URGENCY`, `MONEY`). |
| **Fig 7.0** | **Threat Fingerprint & Risk Signals** | Detected risk signals list | Displays actionable signal chips with severity indicators (e.g., "Suspicious URL: +35 pts", "Urgency Trigger: +20 pts"). |
| **Fig 8.0** | **Message Intelligence & Action Protocol** | Structural stats and defense recommendations | Renders character count, uppercase ratio, links count, and recommended steps ("Block sender, do not click links"). |
| **Fig 9.0** | **Archive Audit Trail** | Archive tab view with populated SQLite records | Displays list of historical analysis cards, search bar, prediction dropdown, and risk level filter. |
| **Fig 10.0** | **Investigation Detail Modal / Drawer** | Inspection view of a specific saved record | Shows complete stored forensic metadata, timestamps, token breakdown, and action protocol without re-running ML. |
| **Fig 11.0** | **Real-Time Insights & Visualizations** | Insights tab view with aggregated SQLite telemetry | Displays 4 summary metric cards, average confidence & threat score, Chart.js Detection Activity timeline, Threat Distribution donut chart, and ranked indicators. |
| **Fig 12.0** | **Mobile Responsive View** | Dashboard rendered at 390px (Mobile Viewport) | Single-column fluid layout, readable fonts, collapsible navigation, accessible buttons, and responsive charts. |

---

### Verification Checklist:
- [x] All screenshots captured directly from the live application without synthetic graphics.
- [x] High-contrast readability verified across both Dark Cyber and Light themes.
- [x] Real SQLite calculations shown in Archive and Insights (no hardcoded mockup statistics).
- [x] XSS payloads verified as plain escaped text in UI figures.
