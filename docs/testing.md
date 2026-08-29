# System Test Plan & Quality Assurance Report

This document records the functional verification test cases (TC01–TC17), security tests, automated regression suite results, and system validation checks executed on the **Spam SMS Filtering System (SMS SENTINEL)**.

---

## 1. Automated Test Suite Summary

- **Test Framework**: Python `unittest`
- **Total Test Cases**: 42 automated tests across 5 test suites
- **Execution Command**: `python -m unittest discover -s tests -v`
- **Overall Result**: **42 / 42 PASSED (100% Pass Rate)**
- **Test Suite Files**:
  1. `tests/test_pipeline.py`: Core ML inference pipeline and API health smoke tests.
  2. `tests/test_xray.py`: Deterministic heuristics, threat scoring, and token extraction.
  3. `tests/test_qa_suite.py`: Defensive boundaries, Unicode/emoji stability, XSS neutralization.
  4. `tests/test_phase6_database_archive.py`: SQLite persistence, filtering, pagination, and deletion.
  5. `tests/test_phase7_insights_realtime.py`: Real-time SQL aggregations, date grouping, and averages.

---

## 2. Functional Test Cases (TC01 – TC17)

| Test Case ID | Test Objective | Test Steps / Input | Expected Result | Actual Result | Status |
|---|---|---|---|---|---|
| **TC01** | Home page loads successfully | Open `http://127.0.0.1:5000/` in browser | HTTP 200, Web dashboard renders with Scan console and live status pulse. | Dashboard rendered cleanly without console errors. | **PASS** |
| **TC02** | Empty / whitespace SMS rejected | Submit empty string `""` or `"   "` to Scan console | Button remains disabled or API returns HTTP 400 with validation message. | HTTP 400 `{"error": "Message cannot be empty."}` returned and displayed. | **PASS** |
| **TC03** | Valid SMS submitted | Enter standard text message and click "Analyze Message" | Button enters loading state, API processes message, returns HTTP 200. | Sub-millisecond response received with full classification payload. | **PASS** |
| **TC04** | Obvious spam classified | Input: *"URGENT! You have won $10,000. Claim now at http://bit.ly/prize"* | Verdict: `SPAM`, Confidence $> 95\%$, Threat Score $> 80$ (HIGH RISK). | Verdict `SPAM`, Confidence `99.9%`, Threat Score `95 / 100`. | **PASS** |
| **TC05** | Legitimate SMS classified | Input: *"Hey, are you free for dinner at 7 PM tonight?"* | Verdict: `NOT SPAM`, Confidence $> 90\%$, Threat Score $< 10$ (LOW RISK). | Verdict `NOT SPAM`, Confidence `99.5%`, Threat Score `4 / 100`. | **PASS** |
| **TC06** | Model confidence displayed | Perform any analysis | Model confidence percentage rendered with visual progress bar. | Rendered formatted percentage (e.g., `99.9%`) on result card. | **PASS** |
| **TC07** | Risk indicators generated | Input: *"Action Required: Bank account suspended. Verify at https://bank-sec.cc"* | Extracts signals: `Suspicious URL`, `Urgency`, `Call to Action`. | Correctly generated 3 color-coded risk indicators with severity tags. | **PASS** |
| **TC08** | Message X-Ray displayed | Perform analysis | Token inspector renders individual tokens color-coded by threat contribution. | Visual token chips rendered with semantic threat highlights. | **PASS** |
| **TC09** | Analysis persisted in SQLite | Analyze message | Analysis record inserted into `analyses` table with unique auto-increment ID. | SQLite record verified with exact prediction, confidence, and timestamps. | **PASS** |
| **TC10** | Archive loads audit records | Click "ARCHIVE" tab | Archive loads stored investigations with total record count and badges. | Loaded paginated audit cards matching database records. | **PASS** |
| **TC11** | Archive keyword search works | Enter search term `"prize"` in Archive search input | Filters cards in real-time matching message text containing `"prize"`. | Search filtered instantly with proper debouncing and count update. | **PASS** |
| **TC12** | Archive multi-criteria filters work | Select Prediction: `Spam Only`, Risk: `High Risk` | Shows only records matching `is_spam = 1` and `threat_score >= 67`. | Exact subset returned and rendered matching SQL criteria. | **PASS** |
| **TC13** | Investigation detail opens | Click "Inspect" button on an Archive card | Modal/Drawer opens showing full stored X-Ray, metrics, and timestamps. | Investigation modal displayed complete analysis forensic details. | **PASS** |
| **TC14** | Real-time Insights load | Click "INSIGHTS" tab | Displays aggregated totals, spam rate, averages, and Chart.js visualizations. | Real SQL aggregates rendered; charts displayed without ghosting. | **PASS** |
| **TC15** | Backend failure / network errors handled | Disconnect API or trigger 500 error | User-friendly toast error notification with retry button. | Displayed clean error card: *"Unable to load data. Please retry."* | **PASS** |
| **TC16** | XSS payload treated as text | Input: `<script>alert(1)</script><img src=x onerror=alert(1)>` | Displayed strictly as plain text characters. No script execution. | Rendered as text via `escapeHtml()`. Zero XSS vulnerabilities. | **PASS** |
| **TC17** | Responsive mobile layout works | Test at `360px`, `390px`, `768px`, `1024px`, `1440px` | No horizontal scrolling; components stack cleanly on mobile. | Fluid responsive layout verified across all standard viewport widths. | **PASS** |

---

## 3. Security & Boundary Verification Results

| Security Test | Attack Vector / Scenario | System Defense Mechanism | Verification Result |
|---|---|---|---|
| **SQL Injection** | `' OR 1=1 --`, `'; DROP TABLE analyses; --` in search | Parameterized SQL bindings (`?`) | **IMMUNE** (Treated as literal search string) |
| **Cross-Site Scripting (XSS)** | Injected HTML/JS scripts in SMS body | Strict DOM text escaping & `escapeHtml()` | **IMMUNE** (Rendered as plain text) |
| **Denial of Service (Payload Size)** | HTTP payload $> 16\text{ KB}$ | `app.config['MAX_CONTENT_LENGTH'] = 16384` | **IMMUNE** (Clean HTTP 413 error returned) |
| **Information Disclosure** | Unhandled exception during prediction | Global `@app.errorhandler(500)` generic JSON | **IMMUNE** (No stack traces or file paths leaked) |
| **Clickjacking / Framing** | Embedding dashboard in external `<iframe>` | `X-Frame-Options: SAMEORIGIN` header | **PROTECTED** |
| **MIME Sniffing** | Malicious content-type overriding | `X-Content-Type-Options: nosniff` header | **PROTECTED** |
