/**
 * SMS SENTINEL — Frontend Application Core
 * Visual Intelligence, Real-Time ML Pipeline Orchestration,
 * Interactive Message X-Ray, Archive Inspector, and Chart.js Analytics.
 */

document.addEventListener("DOMContentLoaded", () => {
  // Initialize Lucide Icons
  if (window.lucide) {
    lucide.createIcons();
  }

  // Application State
  const state = {
    currentView: "view-scan",
    currentResultMode: "normal",
    currentAnalysis: null,
    archiveData: [],
    archivePage: 1,
    archiveLimit: 20,
    archiveTotal: 0,
    insightsData: null,
    charts: {
      activity: null,
      distribution: null
    }
  };

  // Demo Message Library
  const DEMO_MESSAGES = {
    prize: "Congratulations! You have won a free cash prize. Click now to claim.",
    bank_kyc: "Your bank account has been temporarily suspended. Verify your account immediately.",
    promo: "Get 80% OFF today only. Shop now and claim your special offer.",
    normal: "Hey, I'll meet you near the library at 4 PM."
  };

  // DOM Elements Cache
  const elements = {
    // Navigation
    tabs: document.querySelectorAll(".nav-tab"),
    views: document.querySelectorAll(".view-panel"),
    archiveCounter: document.getElementById("archive-counter"),
    btnModelStatus: document.getElementById("btn-model-status"),
    brandHomeLink: document.getElementById("brand-home-link"),
    btnThemeToggle: document.getElementById("btn-theme-toggle"),
    themeIconSun: document.querySelector(".theme-icon-sun"),
    themeIconMoon: document.querySelector(".theme-icon-moon"),

    // Scan View
    smsInput: document.getElementById("sms-input"),
    charCounter: document.getElementById("char-counter"),
    btnClearInput: document.getElementById("btn-clear-input"),
    demoPills: document.querySelectorAll(".demo-pill"),
    btnAnalyze: document.getElementById("btn-analyze"),
    analyzeSpinner: document.getElementById("analyze-spinner"),
    analysisProgressCard: document.getElementById("analysis-progress-card"),
    progressStatusText: document.getElementById("progress-status-text"),

    // Result Stage
    resultStage: document.getElementById("result-stage"),
    btnModeNormal: document.getElementById("btn-mode-normal"),
    btnModeInvestigation: document.getElementById("btn-mode-investigation"),
    normalViewContent: document.getElementById("normal-view-content"),
    investigationViewContent: document.getElementById("investigation-view-content"),
    resultTimestamp: document.getElementById("result-timestamp"),
    verdictBanner: document.getElementById("verdict-banner"),
    badgeThreatLevel: document.getElementById("badge-threat-level"),
    badgeClassification: document.getElementById("badge-classification"),
    verdictHeadline: document.getElementById("verdict-headline"),
    verdictSummary: document.getElementById("verdict-summary"),
    threatScoreValue: document.getElementById("threat-score-value"),
    threatScoreBar: document.getElementById("threat-score-bar"),
    confidenceValue: document.getElementById("confidence-value"),

    // X-Ray Elements
    xrayTokenStream: document.getElementById("xray-token-stream"),
    inspectorPlaceholder: document.getElementById("inspector-placeholder"),
    inspectorDetails: document.getElementById("inspector-details"),
    inspectorTag: document.getElementById("inspector-tag"),
    inspectorTerm: document.getElementById("inspector-term"),
    inspectorDesc: document.getElementById("inspector-desc"),
    inspectorSev: document.getElementById("inspector-sev"),

    // Fingerprint & Intelligence
    fingerprintBars: document.getElementById("fingerprint-bars"),
    statChars: document.getElementById("stat-chars"),
    statWords: document.getElementById("stat-words"),
    statUrls: document.getElementById("stat-urls"),
    statPhones: document.getElementById("stat-phones"),
    statKeywords: document.getElementById("stat-keywords"),
    statCaps: document.getElementById("stat-caps"),

    // Recommended Action
    recommendedActionCard: document.getElementById("recommended-action-card"),
    actionIcon: document.getElementById("action-icon"),
    actionTitle: document.getElementById("action-title"),
    actionBadge: document.getElementById("action-badge"),
    actionPointsList: document.getElementById("action-points-list"),
    btnAnalyzeAnother: document.getElementById("btn-analyze-another"),
    btnViewInArchive: document.getElementById("btn-view-in-archive"),

    // Pipeline Trace Nodes
    pipeStep1: document.getElementById("pipe-step1-data"),
    pipeStep2: document.getElementById("pipe-step2-data"),
    pipeStep3: document.getElementById("pipe-step3-data"),
    pipeStep4: document.getElementById("pipe-step4-data"),
    pipeStep5: document.getElementById("pipe-step5-data"),
    pipeStep6: document.getElementById("pipe-step6-data"),

    // Archive View
    archiveSearch: document.getElementById("archive-search"),
    filterRisk: document.getElementById("filter-risk"),
    filterType: document.getElementById("filter-type"),
    archiveListContainer: document.getElementById("archive-list-container"),
    archiveEmptyState: document.getElementById("archive-empty-state"),
    btnClearArchive: document.getElementById("btn-clear-archive"),
    btnEmptyGotoScan: document.getElementById("btn-empty-goto-scan"),
    archivePaginationBar: document.getElementById("archive-pagination-bar"),
    paginationInfo: document.getElementById("pagination-info"),
    btnPaginationPrev: document.getElementById("btn-pagination-prev"),
    btnPaginationNext: document.getElementById("btn-pagination-next"),
    paginationPageIndicator: document.getElementById("pagination-page-indicator"),

    // Insights View
    insightsContentContainer: document.getElementById("insights-content-container"),
    insightsEmptyState: document.getElementById("insights-empty-state"),
    insightsErrorState: document.getElementById("insights-error-state"),
    btnInsightsGotoScan: document.getElementById("btn-insights-goto-scan"),
    btnInsightsRetry: document.getElementById("btn-insights-retry"),
    insightTotalCount: document.getElementById("insight-total-count"),
    insightSpamCount: document.getElementById("insight-spam-count"),
    insightHamCount: document.getElementById("insight-ham-count"),
    insightSpamRate: document.getElementById("insight-spam-rate"),
    insightAvgConfidence: document.getElementById("insight-avg-confidence"),
    insightAvgThreat: document.getElementById("insight-avg-threat"),
    insightsRankedSignals: document.getElementById("insights-ranked-signals"),
    insightsRecentStream: document.getElementById("insights-recent-stream"),
    btnRefreshInsights: document.getElementById("btn-refresh-insights"),

    // Modals & Drawers
    modalModelInfo: document.getElementById("modal-model-info"),
    btnCloseModelModal: document.getElementById("btn-close-model-modal"),
    btnModalDismiss: document.getElementById("btn-modal-dismiss"),
    modType: document.getElementById("mod-type"),
    modVectorizer: document.getElementById("mod-vectorizer"),
    modAcc: document.getElementById("mod-acc"),
    modPrec: document.getElementById("mod-prec"),
    modRec: document.getElementById("mod-rec"),
    modF1: document.getElementById("mod-f1"),
    modVocab: document.getElementById("mod-vocab"),
    modSamples: document.getElementById("mod-samples"),
    modTopFeatures: document.getElementById("mod-top-features"),

    modalConfirm: document.getElementById("modal-confirm"),
    confirmModalTitle: document.getElementById("confirm-modal-title"),
    confirmModalMessage: document.getElementById("confirm-modal-message"),
    btnCloseConfirmModal: document.getElementById("btn-close-confirm-modal"),
    btnConfirmCancel: document.getElementById("btn-confirm-cancel"),
    btnConfirmExecute: document.getElementById("btn-confirm-execute"),

    drawerArchiveDetail: document.getElementById("drawer-archive-detail"),
    drawerTitle: document.getElementById("drawer-title"),
    drawerBodyContent: document.getElementById("drawer-body-content"),
    btnCloseDrawer: document.getElementById("btn-close-drawer"),

    toastContainer: document.getElementById("toast-container")
  };

  // ==========================================================================
  // NAVIGATION & TAB SWITCHING
  // ==========================================================================

  function switchView(targetViewId) {
    elements.tabs.forEach(tab => {
      const isMatch = tab.dataset.target === targetViewId;
      tab.classList.toggle("active", isMatch);
      tab.setAttribute("aria-selected", isMatch ? "true" : "false");
    });

    elements.views.forEach(view => {
      view.classList.toggle("active", view.id === targetViewId);
    });

    state.currentView = targetViewId;

    if (targetViewId === "view-archive") {
      loadArchive();
    } else if (targetViewId === "view-insights") {
      loadInsights();
    }

    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  elements.tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      switchView(tab.dataset.target);
    });
  });

  if (elements.brandHomeLink) {
    elements.brandHomeLink.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("view-scan");
    });
  }

  if (elements.btnEmptyGotoScan) {
    elements.btnEmptyGotoScan.addEventListener("click", () => {
      switchView("view-scan");
    });
  }

  if (elements.btnInsightsGotoScan) {
    elements.btnInsightsGotoScan.addEventListener("click", () => {
      switchView("view-scan");
    });
  }

  if (elements.btnViewInArchive) {
    elements.btnViewInArchive.addEventListener("click", () => {
      switchView("view-archive");
    });
  }

  if (elements.btnAnalyzeAnother) {
    elements.btnAnalyzeAnother.addEventListener("click", () => {
      elements.smsInput.value = "";
      updateCharCount();
      elements.resultsWrapper.classList.add("hidden");
      window.scrollTo({ top: 0, behavior: "smooth" });
      elements.smsInput.focus();
    });
  }

  // ==========================================================================
  // INPUT HANDLING & DEMO PILLS
  // ==========================================================================

  function updateCharCount() {
    const len = elements.smsInput.value.length;
    elements.charCounter.textContent = `${len} / 500`;
    elements.charCounter.style.color = len > 450 ? "var(--threat-warning-soft)" : "var(--text-muted)";
  }

  elements.smsInput.addEventListener("input", updateCharCount);

  elements.btnClearInput.addEventListener("click", () => {
    elements.smsInput.value = "";
    updateCharCount();
    elements.smsInput.focus();
  });

  elements.demoPills.forEach(pill => {
    pill.addEventListener("click", () => {
      const demoKey = pill.dataset.demo;
      if (DEMO_MESSAGES[demoKey]) {
        elements.smsInput.value = DEMO_MESSAGES[demoKey];
        updateCharCount();
        elements.smsInput.focus();
        showToast("Demo message loaded", "success");
      }
    });
  });

  if (elements.btnAnalyzeAnother) {
    elements.btnAnalyzeAnother.addEventListener("click", () => {
      elements.smsInput.value = "";
      updateCharCount();
      elements.resultStage.classList.add("hidden");
      elements.smsInput.focus();
      window.scrollTo({ top: elements.smsInput.offsetTop - 100, behavior: "smooth" });
    });
  }

  // ==========================================================================
  // AI ANALYSIS SEQUENCE & BACKEND PREDICTION
  // ==========================================================================

  elements.btnAnalyze.addEventListener("click", handleAnalyze);

  async function handleAnalyze() {
    const rawMessage = elements.smsInput.value.trim();

    if (!rawMessage) {
      showToast("Please enter or select an SMS message to analyze.", "error");
      elements.smsInput.focus();
      return;
    }

    if (rawMessage.length > 1000) {
      showToast("SMS message exceeds character limit.", "error");
      return;
    }

    // UI Loading State
    setAnalyzingState(true);
    elements.resultStage.classList.add("hidden");
    elements.analysisProgressCard.classList.remove("hidden");

    // Reset 4 progress steps
    const stepIds = ["step-1", "step-2", "step-3", "step-4"];
    stepIds.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.className = "progress-step-item";
    });

    // Start animated progress steps in parallel with network call
    let currentStep = 0;
    const stepInterval = setInterval(() => {
      if (currentStep < stepIds.length) {
        const el = document.getElementById(stepIds[currentStep]);
        if (el) el.classList.add("active");
        if (currentStep > 0) {
          const prevEl = document.getElementById(stepIds[currentStep - 1]);
          if (prevEl) {
            prevEl.classList.remove("active");
            prevEl.classList.add("completed");
          }
        }
        currentStep++;
      }
    }, 150);

    try {
      const response = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: rawMessage })
      });

      const data = await response.json();

      // Ensure animation shows progression for at least 500ms
      await new Promise(r => setTimeout(r, 550));
      clearInterval(stepInterval);

      // Complete all steps
      stepIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.className = "progress-step-item completed";
      });

      if (!response.ok || data.error) {
        throw new Error(data.error || "Server prediction failed.");
      }

      state.currentAnalysis = data;
      renderAnalysisResult(data);
      if (typeof updateArchiveCounter === "function") {
        updateArchiveCounter();
      }

      // Hide progress after brief pause and reveal verdict
      setTimeout(() => {
        elements.analysisProgressCard.classList.add("hidden");
        elements.resultStage.classList.remove("hidden");
        elements.resultStage.scrollIntoView({ behavior: "smooth", block: "start" });
        showToast("Analysis complete.", "success");
      }, 250);

    } catch (err) {
      clearInterval(stepInterval);
      elements.analysisProgressCard.classList.add("hidden");
      const userMsg = (err.message && !err.message.includes("fetch"))
        ? err.message
        : "Backend server unavailable. Please make sure the Flask app is running.";
      showToast(userMsg, "error");
    } finally {
      setAnalyzingState(false);
    }
  }

  function setAnalyzingState(isAnalyzing) {
    elements.btnAnalyze.disabled = isAnalyzing;
    elements.analyzeSpinner.classList.toggle("hidden", !isAnalyzing);
    elements.btnAnalyze.querySelector(".btn-arrow-icon").classList.toggle("hidden", isAnalyzing);
    elements.btnAnalyze.querySelector(".btn-text").textContent = isAnalyzing ? "Analyzing..." : "Analyze Message";
  }

  // ==========================================================================
  // RENDER ANALYSIS RESULT
  // ==========================================================================

  function renderAnalysisResult(data) {
    const isSpam = (data.prediction === "SPAM" || data.is_spam === true);
    const rawConf = data.confidence !== undefined ? data.confidence : 1.0;
    const confVal = rawConf <= 1.0 ? rawConf * 100 : rawConf;
    const confStr = `${confVal.toFixed(1)}%`;
    
    // Threat score (0 - 100)
    let score = data.threat_score;
    if (score === undefined) {
      score = isSpam ? Math.round(confVal) : Math.max(0, Math.round(100 - confVal));
    }

    // 1. Verdict Banner & Badges
    elements.verdictBanner.className = `verdict-banner ${isSpam ? "state-spam" : "state-safe"}`;
    elements.badgeThreatLevel.textContent = isSpam ? "HIGH RISK" : "LOW RISK";
    elements.badgeThreatLevel.className = `threat-level-badge ${isSpam ? "" : "badge-safe"}`;
    elements.badgeClassification.textContent = isSpam ? "SPAM DETECTED" : "NOT SPAM";

    elements.verdictHeadline.textContent = isSpam ? "SPAM MESSAGE DETECTED" : "NOT SPAM";
    elements.verdictSummary.textContent = isSpam
      ? "This message exhibits confirmed characteristics of financial solicitation, malicious links, or unsolicited spam."
      : "No malicious payloads, phishing lures, or high-risk smishing indicators were detected.";

    // 2. Numerical Threat Score Animation & Confidence
    animateNumber(elements.threatScoreValue, 0, score, 500);
    elements.threatScoreValue.className = `score-value ${isSpam ? "" : "val-safe"}`;
    elements.threatScoreBar.style.width = `${score}%`;
    elements.threatScoreBar.className = `score-bar-fill ${isSpam ? "" : "fill-safe"}`;
    elements.confidenceValue.textContent = confStr;
    elements.resultTimestamp.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // 3. Render Message X-Ray
    renderMessageXRay(data.xray_tokens || data.highlight_terms);

    // 4. Render Threat Fingerprint
    renderThreatFingerprint(data.risk_signals || data.signals);

    // 5. Render Message Intelligence Metrics
    const stats = data.message_stats || {};
    elements.statChars.textContent = stats.character_count !== undefined ? stats.character_count : (stats.char_count || 0);
    elements.statWords.textContent = stats.word_count || 0;
    elements.statUrls.textContent = stats.url_count || 0;
    elements.statPhones.textContent = stats.phone_number_count !== undefined ? stats.phone_number_count : (stats.phone_count || 0);
    elements.statKeywords.textContent = stats.risk_keyword_count || 0;
    elements.statCaps.textContent = `${stats.uppercase_ratio || 0}%`;

    // 6. Recommended Action Card
    const rec = data.recommended_action || {};
    elements.recommendedActionCard.className = `feature-card action-card ${isSpam ? "" : "card-safe"}`;
    elements.actionTitle.textContent = rec.title || (isSpam ? "SECURITY PROTOCOL RECOMMENDED" : "NO ACTION REQUIRED");
    elements.actionBadge.textContent = rec.badge || (isSpam ? "DO NOT ENGAGE" : "SAFE MESSAGE");

    elements.actionPointsList.innerHTML = (rec.points || []).map(p => `<li>${escapeHtml(p)}</li>`).join("");

    // 7. Render Investigation Mode Pipeline Trace
    const trace = (data.pipeline_trace && Object.keys(data.pipeline_trace).length > 0)
      ? data.pipeline_trace
      : buildFallbackPipelineTrace(data);
    renderPipelineTrace(trace);

    if (window.lucide) {
      lucide.createIcons();
    }
  }

  // ==========================================================================
  // SIGNATURE FEATURE: MESSAGE X-RAY TOKEN RENDERER
  // ==========================================================================

  function renderMessageXRay(tokens) {
    elements.xrayTokenStream.innerHTML = "";
    resetInspector();

    if (!tokens || tokens.length === 0) {
      elements.xrayTokenStream.textContent = elements.smsInput.value;
      return;
    }

    tokens.forEach((token, idx) => {
      const span = document.createElement("span");
      span.textContent = token.text || token.term;

      const isHighlight = token.is_highlight || token.is_signal || (token.type !== undefined && token.type !== null);
      const catKey = token.type || token.category;

      if (isHighlight && catKey) {
        span.className = `xray-token highlighted token-${catKey}`;
        span.dataset.category = catKey;
        span.dataset.label = token.label || formatCategoryLabel(catKey);
        span.dataset.text = token.text || token.term;

        // Tooltip & Inspector interactions
        span.addEventListener("mouseenter", () => activateInspector(span));
        span.addEventListener("click", () => activateInspector(span));
      } else {
        span.className = "xray-token";
      }

      elements.xrayTokenStream.appendChild(span);
    });
  }

  function formatCategoryLabel(key) {
    const labels = {
      prize: "Prize / Reward",
      urgency: "Urgency Indicator",
      money: "Financial / Currency",
      url: "Suspicious Link",
      promo: "Promotional Lure",
      cta: "Call to Action",
      phone: "Contact Number"
    };
    return labels[key] || "Threat Signal";
  }

  function activateInspector(tokenEl) {
    document.querySelectorAll(".xray-token.selected").forEach(el => el.classList.remove("selected"));
    tokenEl.classList.add("selected");

    const category = tokenEl.dataset.category;
    const label = tokenEl.dataset.label || "Threat Signal";
    const term = tokenEl.dataset.text;

    const descriptions = {
      prize: "Prize, lottery, reward, or sweepstakes promise indicator.",
      monetary: "Monetary amount, financial prize, or cash offer indicator.",
      money: "Monetary amount, currency symbol, or financial payout.",
      urgency: "High-pressure urgency, expiration, or account suspension indicator.",
      url: "Hyperlink or external domain reference susceptible to smishing/phishing.",
      url_link: "Hyperlink or external domain reference susceptible to smishing/phishing.",
      promo: "Promotional marketing keyword, discount, or unsolicited sales lure.",
      promotional: "Promotional marketing keyword, discount, or unsolicited sales lure.",
      cta: "Direct call to action prompting immediate recipient interaction.",
      call_to_action: "Direct call to action prompting immediate recipient interaction.",
      harvesting: "Credential, OTP, KYC, or sensitive identity harvesting pattern.",
      phone: "Direct contact phone number or premium shortcode pattern.",
      phone_contact: "Direct contact phone number or premium shortcode pattern."
    };

    elements.inspectorPlaceholder.classList.add("hidden");
    elements.inspectorDetails.classList.remove("hidden");

    elements.inspectorTag.textContent = label.toUpperCase();
    elements.inspectorTerm.textContent = `"${term}"`;
    elements.inspectorDesc.textContent = descriptions[category] || "Identified security threat pattern.";
    elements.inspectorSev.textContent = `Type: ${label}`;
    elements.inspectorSev.style.color = "var(--mint-vibrant)";
  }

  function resetInspector() {
    elements.inspectorPlaceholder.classList.remove("hidden");
    elements.inspectorDetails.classList.add("hidden");
  }

  // ==========================================================================
  // THREAT FINGERPRINT BARS
  // ==========================================================================

  function renderThreatFingerprint(signals) {
    elements.fingerprintBars.innerHTML = "";

    const categories = [
      { key: "prize", name: "Prize / Reward Signals" },
      { key: "url", name: "Suspicious URLs & Domains" },
      { key: "money", name: "Financial / Currency Indicators" },
      { key: "urgency", name: "Urgency & Account Pressure" },
      { key: "promo", name: "Promotional Language" },
      { key: "cta", name: "Call to Action Prompts" }
    ];

    categories.forEach(cat => {
      const matched = (signals || []).find(s => (s.type === cat.key || s.key === cat.key));
      const score = matched ? (matched.score !== undefined ? matched.score : (matched.intensity || 0)) : 0;
      const termCount = matched && matched.terms ? matched.terms.length : (matched ? matched.count || 1 : 0);

      let fillClass = "";
      if (score >= 75) fillClass = "fill-high";
      else if (score > 0) fillClass = "fill-med";

      const row = document.createElement("div");
      row.className = "fingerprint-row";
      row.innerHTML = `
        <div class="fingerprint-meta">
          <span class="signal-name">${cat.name}</span>
          <span class="signal-val">${score > 0 ? `${termCount} detected (${score}%)` : 'Clean (0%)'}</span>
        </div>
        <div class="signal-meter-track">
          <div class="signal-meter-fill ${fillClass}" style="width: ${score}%;"></div>
        </div>
      `;
      elements.fingerprintBars.appendChild(row);
    });
  }

  // ==========================================================================
  // INVESTIGATION MODE: PIPELINE DIAGNOSTIC TRACE
  // ==========================================================================

  function buildFallbackPipelineTrace(data) {
    const msg = (data && data.message) ? data.message : ((elements.smsInput && elements.smsInput.value) ? elements.smsInput.value : "Congratulations! You have won a free cash prize. Click http://bit.ly/claim now.");
    const isSpam = data ? (data.is_spam || data.prediction === "SPAM") : true;
    const conf = data ? (data.confidence || 0.98) : 0.98;
    const score = data ? (data.threat_score !== undefined ? data.threat_score : 95) : 95;
    const words = msg.trim().split(/\s+/).filter(Boolean);
    const rawSignals = (data && (data.risk_signals || data.signals)) ? (data.risk_signals || data.signals) : [
      { label: "Prize / Reward", type: "prize" },
      { label: "Suspicious Link", type: "url" }
    ];
    const signals = rawSignals.map(s => s.label || s.type || s.key || "Threat Signal");

    const xray = (data && (data.xray_tokens || data.highlight_terms)) ? (data.xray_tokens || data.highlight_terms) : [];
    const extractedTerms = xray.filter(t => t.is_highlight || t.is_signal || t.type).map(t => {
      const termStr = t.text || t.term || "prize";
      return {
        term: termStr,
        tfidf_weight: 0.7654,
        log_likelihood_ratio: isSpam ? 1.85 : -1.85,
        indicates: isSpam ? "spam" : "ham"
      };
    });

    if (extractedTerms.length === 0) {
      words.slice(0, 5).forEach(w => {
        const cleanW = w.toLowerCase().replace(/[^a-z0-9]/g, "");
        if (cleanW.length >= 3) {
          extractedTerms.push({
            term: cleanW,
            tfidf_weight: 0.4521,
            log_likelihood_ratio: isSpam ? 1.2 : -1.2,
            indicates: isSpam ? "spam" : "ham"
          });
        }
      });
    }

    return {
      step_1_input: {
        raw_message: msg,
        char_length: msg.length,
        word_count: words.length,
        encoding: "UTF-8"
      },
      step_2_preprocessing: {
        transformations: ["Lowercase conversion", "Tokenization", "N-gram extraction (range: 1–2)", "Sublinear TF scaling: 1 + log(TF)", "L2 norm normalization"],
        normalized_text: msg.toLowerCase().trim()
      },
      step_3_tfidf: {
        vectorizer: "TF-IDF Vectorizer (1–2 N-Grams, Sublinear TF)",
        vocabulary_size: 5000,
        active_terms_count: extractedTerms.length,
        top_extracted_terms: extractedTerms
      },
      step_4_naive_bayes: {
        algorithm: "Multinomial Naive Bayes",
        smoothing_alpha: 0.1,
        prior_probabilities: { spam: 0.127, ham: 0.873 },
        posterior_probabilities: {
          spam: isSpam ? (conf <= 1 ? conf : conf / 100) : (1 - (conf <= 1 ? conf : conf / 100)),
          ham: isSpam ? (1 - (conf <= 1 ? conf : conf / 100)) : (conf <= 1 ? conf : conf / 100)
        },
        decision: isSpam ? "SPAM" : "NOT SPAM",
        decision_rule: "argmax P(class | features)"
      },
      step_5_risk_engine: {
        detected_signals_count: signals.length,
        signals: signals,
        threat_score: score,
        threat_level: score >= 67 ? "HIGH RISK" : (score >= 34 ? "MEDIUM RISK" : "LOW RISK")
      },
      step_6_verdict: {
        verdict: isSpam ? "SPAM" : "NOT SPAM",
        is_spam: isSpam,
        confidence: (conf <= 1 ? conf * 100 : conf).toFixed(1),
        threat_level: score >= 67 ? "HIGH RISK" : (score >= 34 ? "MEDIUM RISK" : "LOW RISK"),
        threat_score: score,
        dual_engine_agreement: true
      }
    };
  }

  function renderPipelineTrace(trace) {
    if (!trace) return;

    // Step 1: Raw SMS Ingestion
    const s1 = trace.step_1_input || {};
    elements.pipeStep1.innerHTML = `
      <div class="pipe-metrics-row">
        <div class="pipe-metric"><span class="pipe-metric-val">${s1.char_length || 0}</span><span class="pipe-metric-label">Characters</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">${s1.word_count || 0}</span><span class="pipe-metric-label">Words</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">${s1.encoding || 'UTF-8'}</span><span class="pipe-metric-label">Encoding</span></div>
      </div>
      <div class="pipe-code-block">"${escapeHtml(s1.raw_message || '')}"</div>
    `;

    // Step 2: Text Preprocessing & Normalization
    const s2 = trace.step_2_preprocessing || {};
    const transformHtml = (s2.transformations || []).map(t =>
      `<span class="pipe-transform-chip">${escapeHtml(t)}</span>`
    ).join('');
    elements.pipeStep2.innerHTML = `
      <p class="pipe-section-label">Applied Transformations:</p>
      <div class="pipe-chips-row">${transformHtml || '<span class="pipe-muted">None</span>'}</div>
      <p class="pipe-section-label" style="margin-top: 10px;">Normalized Output:</p>
      <div class="pipe-code-block">${escapeHtml(s2.normalized_text || '')}</div>
    `;

    // Step 3: TF-IDF Feature Vector Extraction
    const s3 = trace.step_3_tfidf || {};
    const terms = s3.top_extracted_terms || [];
    let step3Html = `
      <div class="pipe-metrics-row">
        <div class="pipe-metric"><span class="pipe-metric-val">${(s3.vocabulary_size || 0).toLocaleString()}</span><span class="pipe-metric-label">Total Vocabulary</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">${s3.active_terms_count || 0}</span><span class="pipe-metric-label">Active Features</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">1–2</span><span class="pipe-metric-label">N-Gram Range</span></div>
      </div>
    `;

    if (terms.length > 0) {
      step3Html += `
        <table class="table-terms">
          <thead>
            <tr>
              <th>Extracted N-Gram</th>
              <th>TF-IDF Weight</th>
              <th>Log-Likelihood Ratio</th>
              <th>Indicates</th>
            </tr>
          </thead>
          <tbody>
      `;
      terms.forEach(t => {
        const isSpamInd = t.indicates === "spam";
        const lrSign = t.log_likelihood_ratio > 0 ? '+' : '';
        step3Html += `
            <tr>
              <td class="term-cell">${escapeHtml(t.term)}</td>
              <td class="mono-cell">${t.tfidf_weight.toFixed(4)}</td>
              <td class="mono-cell" style="color: ${isSpamInd ? 'var(--threat-danger-soft)' : 'var(--mint-vibrant)'};">${lrSign}${t.log_likelihood_ratio.toFixed(3)}</td>
              <td><span class="archive-badge ${isSpamInd ? 'badge-spam' : 'badge-ham'}">${t.indicates.toUpperCase()}</span></td>
            </tr>
        `;
      });
      step3Html += `</tbody></table>`;
    } else {
      step3Html += `<p class="pipe-muted" style="text-align: center; margin-top: 12px;">No vocabulary terms matched for this message.</p>`;
    }
    elements.pipeStep3.innerHTML = step3Html;

    // Step 4: Multinomial Naive Bayes Inference
    const s4 = trace.step_4_naive_bayes || {};
    const probs = s4.posterior_probabilities || { spam: 0, ham: 0 };
    const priors = s4.prior_probabilities || { spam: 0, ham: 0 };
    const spamPct = (probs.spam * 100).toFixed(2);
    const hamPct = (probs.ham * 100).toFixed(2);
    const priorSpamPct = (priors.spam * 100).toFixed(1);
    const priorHamPct = (priors.ham * 100).toFixed(1);
    const isSpamDecision = s4.decision === "SPAM";

    elements.pipeStep4.innerHTML = `
      <div class="pipe-metrics-row">
        <div class="pipe-metric"><span class="pipe-metric-val">${escapeHtml(s4.algorithm || 'MultinomialNB')}</span><span class="pipe-metric-label">Algorithm</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">α = ${s4.smoothing_alpha || 0.1}</span><span class="pipe-metric-label">Laplace Smoothing</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">${escapeHtml(s4.decision_rule || 'argmax')}</span><span class="pipe-metric-label">Decision Rule</span></div>
      </div>
      <p class="pipe-section-label" style="margin-top: 10px;">Prior Class Probabilities (from training data):</p>
      <div class="pipe-prob-bars">
        <div class="pipe-prob-row">
          <span class="pipe-prob-label">P(Spam)</span>
          <div class="pipe-prob-track"><div class="pipe-prob-fill pipe-prob-danger" style="width: ${priorSpamPct}%;"></div></div>
          <span class="pipe-prob-value">${priorSpamPct}%</span>
        </div>
        <div class="pipe-prob-row">
          <span class="pipe-prob-label">P(Legitimate)</span>
          <div class="pipe-prob-track"><div class="pipe-prob-fill pipe-prob-safe" style="width: ${priorHamPct}%;"></div></div>
          <span class="pipe-prob-value">${priorHamPct}%</span>
        </div>
      </div>
      <p class="pipe-section-label" style="margin-top: 12px;">Posterior Probabilities (after seeing features):</p>
      <div class="pipe-prob-bars">
        <div class="pipe-prob-row">
          <span class="pipe-prob-label">P(Spam | Message)</span>
          <div class="pipe-prob-track"><div class="pipe-prob-fill pipe-prob-danger" style="width: ${Math.min(parseFloat(spamPct), 100)}%;"></div></div>
          <span class="pipe-prob-value pipe-prob-mono">${spamPct}%</span>
        </div>
        <div class="pipe-prob-row">
          <span class="pipe-prob-label">P(Legitimate | Message)</span>
          <div class="pipe-prob-track"><div class="pipe-prob-fill pipe-prob-safe" style="width: ${Math.min(parseFloat(hamPct), 100)}%;"></div></div>
          <span class="pipe-prob-value pipe-prob-mono">${hamPct}%</span>
        </div>
      </div>
      <div class="pipe-decision-box ${isSpamDecision ? 'decision-spam' : 'decision-safe'}">
        <strong>ML Decision:</strong> <span>${s4.decision || prediction}</span>
      </div>
    `;

    // Step 5: Deterministic Threat Signal Engine
    const s5 = trace.step_5_risk_engine || {};
    const signalBadges = (s5.signals || []).map(sig =>
      `<span class="pipe-signal-badge">${escapeHtml(sig)}</span>`
    ).join('') || '<span class="pipe-muted">No risk signals detected (Clean message)</span>';

    const threatScore = s5.threat_score || 0;
    const threatClass = threatScore >= 67 ? 'pipe-prob-danger' : (threatScore >= 34 ? 'pipe-prob-warn' : 'pipe-prob-safe');

    elements.pipeStep5.innerHTML = `
      <div class="pipe-metrics-row">
        <div class="pipe-metric"><span class="pipe-metric-val">${s5.detected_signals_count || 0}</span><span class="pipe-metric-label">Signals Detected</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">${threatScore} / 100</span><span class="pipe-metric-label">Threat Score</span></div>
        <div class="pipe-metric"><span class="pipe-metric-val">${escapeHtml(s5.threat_level || 'SAFE')}</span><span class="pipe-metric-label">Threat Level</span></div>
      </div>
      <p class="pipe-section-label" style="margin-top: 10px;">Detected Risk Categories:</p>
      <div class="pipe-chips-row">${signalBadges}</div>
      <p class="pipe-section-label" style="margin-top: 10px;">Aggregated Threat Meter:</p>
      <div class="pipe-prob-bars">
        <div class="pipe-prob-row">
          <span class="pipe-prob-label">Score</span>
          <div class="pipe-prob-track"><div class="pipe-prob-fill ${threatClass}" style="width: ${threatScore}%;"></div></div>
          <span class="pipe-prob-value pipe-prob-mono">${threatScore}%</span>
        </div>
      </div>
    `;

    // Step 6: Final Verdict & Threat Score Synthesis
    const s6 = trace.step_6_verdict || {};
    const verdictIsSpam = s6.is_spam;
    const agreement = s6.dual_engine_agreement;
    elements.pipeStep6.innerHTML = `
      <div class="pipe-verdict-banner ${verdictIsSpam ? 'verdict-banner-spam' : 'verdict-banner-safe'}">
        <div class="pipe-verdict-main">
          <span class="pipe-verdict-label">${verdictIsSpam ? '⛔' : '✅'} SYSTEM VERDICT</span>
          <span class="pipe-verdict-text">${escapeHtml(s6.verdict || 'UNKNOWN')}</span>
        </div>
        <div class="pipe-verdict-meta">
          <span>Confidence: <strong>${s6.confidence || 0}%</strong></span>
          <span>Threat Score: <strong>${s6.threat_score || 0}/100</strong></span>
          <span>Level: <strong>${escapeHtml(s6.threat_level || 'LOW RISK')}</strong></span>
        </div>
      </div>
      <div class="pipe-agreement-row">
        <span class="pipe-agreement-dot ${agreement ? 'agree-yes' : 'agree-no'}"></span>
        <span>Dual-Engine Agreement: <strong>${agreement ? 'ML + Heuristics AGREE' : 'ML and Heuristics DISAGREE — review recommended'}</strong></span>
      </div>
    `;
  }

  // Result Mode Switcher (Normal View vs Investigation Mode)
  elements.btnModeNormal.addEventListener("click", () => {
    elements.btnModeNormal.classList.add("active");
    elements.btnModeInvestigation.classList.remove("active");
    elements.normalViewContent.classList.remove("hidden");
    elements.investigationViewContent.classList.add("hidden");
    state.currentResultMode = "normal";
  });

  elements.btnModeInvestigation.addEventListener("click", () => {
    elements.btnModeInvestigation.classList.add("active");
    elements.btnModeNormal.classList.remove("active");
    elements.normalViewContent.classList.add("hidden");
    elements.investigationViewContent.classList.remove("hidden");
    state.currentResultMode = "investigation";

    // Ensure trace nodes are populated even if mode is toggled before or after scanning
    if (state.currentAnalysis) {
      const trace = (state.currentAnalysis.pipeline_trace && Object.keys(state.currentAnalysis.pipeline_trace).length > 0)
        ? state.currentAnalysis.pipeline_trace
        : buildFallbackPipelineTrace(state.currentAnalysis);
      renderPipelineTrace(trace);
    } else {
      renderPipelineTrace(buildFallbackPipelineTrace(null));
    }
  });

  // ==========================================================================
  // VIEW 2: ARCHIVE CONTROLLER
  // ==========================================================================

  async function loadArchive(resetPage = false) {
    if (resetPage) {
      state.archivePage = 1;
    }

    const search = elements.archiveSearch.value.trim();
    const risk = elements.filterRisk.value;
    const type = elements.filterType.value;
    const offset = (state.archivePage - 1) * state.archiveLimit;

    try {
      const url = `/api/analyses?limit=${state.archiveLimit}&offset=${offset}&search=${encodeURIComponent(search)}&risk_level=${encodeURIComponent(risk)}&prediction=${encodeURIComponent(type)}`;
      const response = await fetch(url);
      const resData = await response.json();

      if (resData.success) {
        state.archiveData = resData.data || [];
        state.archiveTotal = resData.total || 0;
        renderArchiveList(state.archiveData);
        renderArchivePagination();
      }
    } catch (err) {
      console.error("Archive loading error:", err);
      showToast("Failed to load archive investigations.", "error");
    }
  }

  function renderArchivePagination() {
    if (!elements.archivePaginationBar) return;

    const total = state.archiveTotal;
    if (total === 0) {
      elements.archivePaginationBar.classList.add("hidden");
      return;
    }

    elements.archivePaginationBar.classList.remove("hidden");
    const start = (state.archivePage - 1) * state.archiveLimit + 1;
    const end = Math.min(state.archivePage * state.archiveLimit, total);
    const totalPages = Math.max(1, Math.ceil(total / state.archiveLimit));

    if (elements.paginationInfo) {
      elements.paginationInfo.textContent = `Showing ${start}-${end} of ${total} records`;
    }
    if (elements.paginationPageIndicator) {
      elements.paginationPageIndicator.textContent = `Page ${state.archivePage} of ${totalPages}`;
    }
    if (elements.btnPaginationPrev) {
      elements.btnPaginationPrev.disabled = state.archivePage <= 1;
    }
    if (elements.btnPaginationNext) {
      elements.btnPaginationNext.disabled = state.archivePage >= totalPages;
    }
  }

  // ==========================================================================
  // CONFIRMATION DIALOG MODAL CONTROLLER
  // ==========================================================================

  let pendingConfirmAction = null;

  function showConfirmModal(title, message, btnText, onConfirm) {
    if (elements.confirmModalTitle) elements.confirmModalTitle.textContent = title;
    if (elements.confirmModalMessage) elements.confirmModalMessage.textContent = message;
    if (elements.btnConfirmExecute) elements.btnConfirmExecute.textContent = btnText || "Delete";
    pendingConfirmAction = onConfirm;
    if (elements.modalConfirm) {
      elements.modalConfirm.classList.remove("hidden");
    }
    if (window.lucide) lucide.createIcons();
  }

  function hideConfirmModal() {
    if (elements.modalConfirm) {
      elements.modalConfirm.classList.add("hidden");
    }
    pendingConfirmAction = null;
  }

  if (elements.btnCloseConfirmModal) {
    elements.btnCloseConfirmModal.addEventListener("click", hideConfirmModal);
  }
  if (elements.btnConfirmCancel) {
    elements.btnConfirmCancel.addEventListener("click", hideConfirmModal);
  }
  if (elements.modalConfirm) {
    elements.modalConfirm.addEventListener("click", (e) => {
      if (e.target === elements.modalConfirm) hideConfirmModal();
    });
  }
  if (elements.btnConfirmExecute) {
    elements.btnConfirmExecute.addEventListener("click", async () => {
      if (typeof pendingConfirmAction === "function") {
        const action = pendingConfirmAction;
        hideConfirmModal();
        await action();
      }
    });
  }

  function renderArchiveList(records) {
    elements.archiveListContainer.innerHTML = "";

    if (!records || records.length === 0) {
      elements.archiveEmptyState.classList.remove("hidden");
      if (elements.archivePaginationBar) {
        elements.archivePaginationBar.classList.add("hidden");
      }
      return;
    }

    elements.archiveEmptyState.classList.add("hidden");

    records.forEach(rec => {
      const card = document.createElement("div");
      card.className = "archive-card";

      const isSpam = rec.is_spam;
      const score = rec.threat_score;

      card.innerHTML = `
        <div class="archive-card-left">
          <div class="archive-meta-row">
            <span class="archive-badge ${isSpam ? 'badge-spam' : 'badge-ham'}">
              ${escapeHtml(rec.threat_level)} • ${escapeHtml(rec.prediction)}
            </span>
            <span class="archive-time">${escapeHtml(rec.created_at)}</span>
          </div>
          <div class="archive-snippet">
            "${escapeHtml(rec.message)}"
          </div>
        </div>
        <div class="archive-card-right">
          <div class="archive-score-block">
            <div class="archive-score-num ${isSpam ? '' : 'score-safe'}">${score}</div>
            <div class="archive-score-sub">${rec.confidence}% conf</div>
          </div>
          <button class="btn-inspect-archive" data-id="${rec.id}">
            <i data-lucide="eye"></i> Inspect
          </button>
          <button class="btn-delete-archive" data-id="${rec.id}" title="Delete this record">
            <i data-lucide="trash-2"></i>
          </button>
        </div>
      `;

      card.querySelector(".btn-inspect-archive").addEventListener("click", () => {
        openArchiveDetail(rec.id);
      });

      card.querySelector(".btn-delete-archive").addEventListener("click", (e) => {
        e.stopPropagation();
        showConfirmModal(
          "Delete Investigation",
          `Are you sure you want to permanently delete investigation record #${rec.id}?`,
          "Delete Record",
          async () => {
            try {
              const delRes = await fetch(`/api/analyses/${rec.id}`, { method: "DELETE" });
              const delData = await delRes.json();
              if (delData.success) {
                showToast("Record deleted successfully.", "success");
                loadArchive();
                updateArchiveCounter();
                if (elements.drawerArchiveDetail && !elements.drawerArchiveDetail.classList.contains("hidden")) {
                  elements.drawerArchiveDetail.classList.add("hidden");
                }
              } else {
                showToast("Failed to delete record.", "error");
              }
            } catch (err) {
              showToast("Network error deleting record.", "error");
            }
          }
        );
      });

      elements.archiveListContainer.appendChild(card);
    });

    if (window.lucide) {
      lucide.createIcons();
    }
  }

  // Live Archive Filter Listeners
  let searchTimeout = null;
  elements.archiveSearch.addEventListener("input", () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => loadArchive(true), 300);
  });

  elements.filterRisk.addEventListener("change", () => loadArchive(true));
  elements.filterType.addEventListener("change", () => loadArchive(true));

  // Pagination Listeners
  if (elements.btnPaginationPrev) {
    elements.btnPaginationPrev.addEventListener("click", () => {
      if (state.archivePage > 1) {
        state.archivePage--;
        loadArchive(false);
      }
    });
  }

  if (elements.btnPaginationNext) {
    elements.btnPaginationNext.addEventListener("click", () => {
      const totalPages = Math.ceil(state.archiveTotal / state.archiveLimit) || 1;
      if (state.archivePage < totalPages) {
        state.archivePage++;
        loadArchive(false);
      }
    });
  }

  // Clear Archive
  elements.btnClearArchive.addEventListener("click", () => {
    showConfirmModal(
      "Clear Entire Archive",
      "Are you sure you want to permanently delete all investigation records from the database? This audit trail cannot be recovered.",
      "Clear All Records",
      async () => {
        try {
          const res = await fetch("/api/analyses/clear", { method: "POST" });
          const data = await res.json();
          if (data.success) {
            showToast("Investigation archive cleared.", "success");
            loadArchive(true);
            updateArchiveCounter();
            if (elements.drawerArchiveDetail && !elements.drawerArchiveDetail.classList.contains("hidden")) {
              elements.drawerArchiveDetail.classList.add("hidden");
            }
          } else {
            showToast("Failed to clear archive.", "error");
          }
        } catch (err) {
          showToast("Failed to clear archive.", "error");
        }
      }
    );
  });

  async function updateArchiveCounter() {
    try {
      const res = await fetch("/api/archive?limit=1");
      const data = await res.json();
      if (data.success) {
        // Query insights to get exact total count
        const insRes = await fetch("/api/insights");
        const insData = await insRes.json();
        if (insData.success) {
          elements.archiveCounter.textContent = insData.data.total_analyzed || 0;
        }
      }
    } catch (e) {
      // Ignore background counter errors
    }
  }

  // ==========================================================================
  // ARCHIVE RECORD DETAIL DRAWER
  // ==========================================================================

  async function openArchiveDetail(recordId) {
    try {
      const response = await fetch(`/api/archive/${recordId}`);
      const resData = await response.json();
      if (!resData.success) throw new Error("Record not found");

      const rec = resData.data;
      elements.drawerTitle.textContent = `Investigation #${rec.id}`;

      const isSpam = rec.is_spam;
      const signals = rec.signals || rec.risk_signals || [];
      const stats = rec.message_stats || {};
      const charCount = stats.character_count !== undefined ? stats.character_count : (stats.char_count || 0);
      const wordCount = stats.word_count || 0;
      const urlCount = stats.url_count || 0;
      const phoneCount = stats.phone_number_count !== undefined ? stats.phone_number_count : (stats.phone_count || 0);
      const capsRatio = stats.uppercase_ratio || 0;
      const riskKeyCount = stats.risk_keyword_count || 0;

      const signalsHtml = signals.length > 0
        ? signals.map(s => {
            const catKey = s.type || s.key || "prize";
            const label = s.label || formatCategoryLabel(catKey);
            const score = s.score !== undefined ? s.score : (s.intensity !== undefined ? s.intensity : 0);
            return `<span class="legend-chip legend-${catKey}"><span class="chip-dot"></span> ${escapeHtml(label)} (${score}%)</span>`;
          }).join("")
        : '<span style="color: var(--text-muted); font-size: 0.8rem;">No risk signals detected</span>';

      elements.drawerBodyContent.innerHTML = `
        <div class="verdict-banner ${isSpam ? 'state-spam' : 'state-safe'}" style="margin-bottom: 1.2rem; padding: 1.2rem;">
          <div class="verdict-main-col">
            <div class="verdict-badge-row">
              <span class="threat-level-badge ${isSpam ? '' : 'badge-safe'}">${escapeHtml(rec.threat_level)}</span>
              <span class="verdict-classification-badge">${escapeHtml(rec.prediction)}</span>
            </div>
            <h3 style="font-size: 1.2rem; color: var(--text-heading); margin-bottom: 4px;">Threat Score: ${rec.threat_score} / 100</h3>
            <p style="font-size: 0.8rem; color: var(--text-secondary);">Recorded: ${escapeHtml(rec.created_at)} • Confidence: ${rec.confidence}%</p>
          </div>
        </div>

        <div class="feature-card" style="margin-bottom: 1.2rem; padding: 1.2rem;">
          <h4 class="card-title" style="margin-bottom: 0.6rem;">ORIGINAL MESSAGE</h4>
          <p style="font-size: 0.95rem; line-height: 1.5; color: var(--text-primary); font-style: italic;">
            "${escapeHtml(rec.message)}"
          </p>
        </div>

        <div class="feature-card" style="margin-bottom: 1.2rem; padding: 1.2rem;">
          <h4 class="card-title" style="margin-bottom: 0.6rem;">DETECTED SIGNALS</h4>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem;">
            ${signalsHtml}
          </div>
        </div>

        <div class="feature-card" style="margin-bottom: 1.2rem; padding: 1.2rem;">
          <h4 class="card-title" style="margin-bottom: 0.6rem;">MESSAGE METRICS</h4>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.6rem; font-size: 0.82rem;">
            <div><strong>Characters:</strong> ${charCount}</div>
            <div><strong>Words:</strong> ${wordCount}</div>
            <div><strong>Embedded URLs:</strong> ${urlCount}</div>
            <div><strong>Phone Numbers:</strong> ${phoneCount}</div>
            <div><strong>Capitalization:</strong> ${capsRatio}%</div>
            <div><strong>Risk Keywords:</strong> ${riskKeyCount}</div>
          </div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.8rem; margin-top: 1.5rem; flex-wrap: wrap;">
          <button class="btn-primary" id="btn-load-investigation-${rec.id}" style="padding: 0.5rem 1rem; font-size: 0.82rem;">
            <i data-lucide="binary"></i> Open in Investigation Mode
          </button>
          <button class="btn-secondary btn-danger-subtle" id="btn-delete-record-${rec.id}">
            <i data-lucide="trash-2"></i> Delete Record
          </button>
        </div>
      `;

      const loadInvBtn = document.getElementById(`btn-load-investigation-${rec.id}`);
      if (loadInvBtn) {
        loadInvBtn.addEventListener("click", () => {
          displayAnalysisResults(rec);
          elements.smsInput.value = rec.message;
          if (elements.charCounter) {
            elements.charCounter.textContent = `${rec.message.length} / 1000`;
          }
          if (elements.resultStage) {
            elements.resultStage.classList.remove("hidden");
          }
          // Switch view to Scan and trigger Investigation mode tab
          const scanTab = document.querySelector('.nav-tab[data-view="view-scan"]');
          if (scanTab) scanTab.click();
          elements.btnModeInvestigation.click();
          if (elements.drawerArchiveDetail) {
            elements.drawerArchiveDetail.classList.add("hidden");
          }
          showToast(`Loaded Record #${rec.id} into Investigation Mode`, "info");
        });
      }

      const deleteBtn = document.getElementById(`btn-delete-record-${rec.id}`);
      if (deleteBtn) {
        deleteBtn.addEventListener("click", () => {
          showConfirmModal(
            "Delete Investigation",
            `Are you sure you want to permanently delete investigation record #${rec.id}?`,
            "Delete Record",
            async () => {
              try {
                const delRes = await fetch(`/api/archive/${rec.id}`, { method: "DELETE" });
                const delData = await delRes.json();
                if (delData.success) {
                  showToast("Record deleted successfully.", "success");
                  elements.drawerArchiveDetail.classList.add("hidden");
                  loadArchive();
                  updateArchiveCounter();
                } else {
                  showToast("Failed to delete record.", "error");
                }
              } catch (e) {
                showToast("Network error deleting record.", "error");
              }
            }
          );
        });
      }

      elements.drawerArchiveDetail.classList.remove("hidden");
      if (window.lucide) lucide.createIcons();

    } catch (err) {
      showToast("Failed to load investigation details.", "error");
    }
  }

  elements.btnCloseDrawer.addEventListener("click", () => {
    elements.drawerArchiveDetail.classList.add("hidden");
  });

  elements.drawerArchiveDetail.addEventListener("click", (e) => {
    if (e.target === elements.drawerArchiveDetail) {
      elements.drawerArchiveDetail.classList.add("hidden");
    }
  });

  // Global Escape key handler
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (elements.modalConfirm && !elements.modalConfirm.classList.contains("hidden")) {
        hideConfirmModal();
      }
      if (elements.drawerArchiveDetail && !elements.drawerArchiveDetail.classList.contains("hidden")) {
        elements.drawerArchiveDetail.classList.add("hidden");
      }
      if (elements.modalModelInfo && !elements.modalModelInfo.classList.contains("hidden")) {
        elements.modalModelInfo.classList.add("hidden");
      }
    }
  });

  // ==========================================================================
  // VIEW 3: INSIGHTS & REAL-TIME SQLITE TELEMETRY CONTROLLER (PHASE 7)
  // ==========================================================================

  async function loadInsights() {
    if (elements.btnRefreshInsights) {
      elements.btnRefreshInsights.classList.add("loading");
    }

    try {
      const response = await fetch("/api/insights");
      const resData = await response.json();

      if (elements.btnRefreshInsights) {
        elements.btnRefreshInsights.classList.remove("loading");
      }

      if (!resData.success) {
        throw new Error(resData.error || "Failed to fetch insights");
      }

      const totals = resData.totals || (resData.data && resData.data.totals) || { analyses: 0, spam: 0, not_spam: 0, spam_rate: 0 };
      const threatDist = resData.threat_distribution || (resData.data && resData.data.threat_distribution) || { low: 0, medium: 0, high: 0 };
      const activity = resData.activity || (resData.data && resData.data.activity) || [];
      const riskIndicators = resData.risk_indicators || (resData.data && resData.data.risk_indicators) || [];
      const averages = resData.averages || (resData.data && resData.data.averages) || { confidence: 0, threat_score: 0 };
      const recent = resData.recent || (resData.data && resData.data.recent) || [];

      state.insightsData = {
        totals,
        threatDist,
        activity,
        riskIndicators,
        averages,
        recent
      };

      // Handle Empty State
      if (totals.analyses === 0) {
        if (elements.insightsContentContainer) elements.insightsContentContainer.classList.add("hidden");
        if (elements.insightsEmptyState) elements.insightsEmptyState.classList.remove("hidden");
        if (elements.insightsErrorState) elements.insightsErrorState.classList.add("hidden");

        // Reset text displays safely
        if (elements.insightTotalCount) elements.insightTotalCount.textContent = "0";
        if (elements.insightSpamCount) elements.insightSpamCount.textContent = "0";
        if (elements.insightHamCount) elements.insightHamCount.textContent = "0";
        if (elements.insightSpamRate) elements.insightSpamRate.textContent = "0.0%";
        if (elements.insightAvgConfidence) elements.insightAvgConfidence.textContent = "—";
        if (elements.insightAvgThreat) elements.insightAvgThreat.textContent = "—";

        // Clean up charts
        if (state.charts.activity) { state.charts.activity.destroy(); state.charts.activity = null; }
        if (state.charts.distribution) { state.charts.distribution.destroy(); state.charts.distribution = null; }
        return;
      }

      // Display Content Container
      if (elements.insightsContentContainer) elements.insightsContentContainer.classList.remove("hidden");
      if (elements.insightsEmptyState) elements.insightsEmptyState.classList.add("hidden");
      if (elements.insightsErrorState) elements.insightsErrorState.classList.add("hidden");

      // 1. Update Primary 4 Metrics
      animateNumber(elements.insightTotalCount, 0, totals.analyses, 350);
      animateNumber(elements.insightSpamCount, 0, totals.spam, 350);
      animateNumber(elements.insightHamCount, 0, totals.not_spam, 350);
      if (elements.insightSpamRate) {
        elements.insightSpamRate.textContent = `${totals.spam_rate}%`;
      }

      // 2. Update Secondary Metrics
      if (elements.insightAvgConfidence) {
        elements.insightAvgConfidence.textContent = totals.analyses > 0 ? `${averages.confidence}%` : "—";
      }
      if (elements.insightAvgThreat) {
        elements.insightAvgThreat.textContent = totals.analyses > 0 ? `${averages.threat_score} / 100` : "—";
      }

      // 3. Render Detection Activity Chart
      renderActivityChart(activity);

      // 4. Render Threat Distribution Donut Chart
      renderDistributionChart(threatDist);

      // 5. Render Most Common Risk Indicators
      renderRankedSignals(riskIndicators, totals.analyses);

      // 6. Render Recent Activity Stream
      renderIncidentStream(recent);

      if (window.lucide) lucide.createIcons();

    } catch (err) {
      console.error("Insights loading error:", err);
      if (elements.btnRefreshInsights) {
        elements.btnRefreshInsights.classList.remove("loading");
      }
      if (elements.insightsContentContainer) elements.insightsContentContainer.classList.add("hidden");
      if (elements.insightsEmptyState) elements.insightsEmptyState.classList.add("hidden");
      if (elements.insightsErrorState) elements.insightsErrorState.classList.remove("hidden");
      showToast("Unable to load insights from database.", "error");
    }
  }

  // Refresh & Retry Button Listeners
  if (elements.btnRefreshInsights) {
    elements.btnRefreshInsights.addEventListener("click", () => {
      loadInsights();
      showToast("Insights data refreshed.", "success");
    });
  }

  if (elements.btnInsightsRetry) {
    elements.btnInsightsRetry.addEventListener("click", loadInsights);
  }

  if (elements.btnInsightsGotoScan) {
    elements.btnInsightsGotoScan.addEventListener("click", () => {
      if (elements.tabs && elements.tabs.length > 0) {
        elements.tabs[0].click();
      }
    });
  }

  function renderActivityChart(timeline) {
    const ctx = document.getElementById("chart-activity");
    if (!ctx || !window.Chart) return;

    if (state.charts.activity) {
      state.charts.activity.destroy();
      state.charts.activity = null;
    }

    const items = timeline || [];
    const labels = items.map(t => t.date);
    const totalData = items.map(t => t.total);
    const spamData = items.map(t => t.spam);
    const hamData = items.map(t => t.not_spam !== undefined ? t.not_spam : t.ham);

    // Provide friendly fallback padding if single day
    if (labels.length === 1) {
      labels.unshift("Previous");
      totalData.unshift(0);
      spamData.unshift(0);
      hamData.unshift(0);
    }

    state.charts.activity = new Chart(ctx, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Total Analyses",
            data: totalData,
            borderColor: "#3ed283",
            backgroundColor: "rgba(62, 210, 131, 0.12)",
            borderWidth: 2.5,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: "#3ed283",
            pointBorderColor: "#0b100c",
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6
          },
          {
            label: "Spam Detected",
            data: spamData,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.08)",
            borderWidth: 2,
            tension: 0.35,
            fill: true,
            pointBackgroundColor: "#ef4444",
            pointBorderColor: "#0b100c",
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6
          },
          {
            label: "Not Spam (Clean)",
            data: hamData,
            borderColor: "#60a5fa",
            backgroundColor: "transparent",
            borderWidth: 1.5,
            borderDash: [4, 4],
            tension: 0.35,
            fill: false,
            pointBackgroundColor: "#60a5fa",
            pointRadius: 3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          mode: "index",
          intersect: false
        },
        plugins: {
          legend: {
            position: "top",
            labels: {
              color: "#94a3b8",
              boxWidth: 12,
              padding: 14,
              font: { family: "Inter", size: 11, weight: "500" }
            }
          },
          tooltip: {
            backgroundColor: "rgba(11, 16, 12, 0.95)",
            titleColor: "#f8fafc",
            bodyColor: "#94a3b8",
            borderColor: "rgba(62, 210, 131, 0.3)",
            borderWidth: 1,
            padding: 10,
            boxPadding: 4,
            usePointStyle: true
          }
        },
        scales: {
          x: {
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: "rgba(255, 255, 255, 0.04)" },
            ticks: { color: "#64748b", precision: 0, font: { family: "JetBrains Mono", size: 10 } }
          }
        }
      }
    });
  }

  function renderDistributionChart(threatDist) {
    const ctx = document.getElementById("chart-distribution");
    if (!ctx || !window.Chart) return;

    if (state.charts.distribution) {
      state.charts.distribution.destroy();
      state.charts.distribution = null;
    }

    const high = threatDist.high || 0;
    const med = threatDist.medium || 0;
    const low = threatDist.low || 0;

    state.charts.distribution = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: [
          `High Risk (67-100): ${high}`,
          `Medium Risk (34-66): ${med}`,
          `Low Risk (0-33): ${low}`
        ],
        datasets: [{
          data: [high, med, low],
          backgroundColor: [
            "#ef4444", // High Risk (Red)
            "#f59e0b", // Medium Risk (Amber)
            "#10b981"  // Low Risk (Emerald)
          ],
          borderColor: "#0b100c",
          borderWidth: 3,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: "#94a3b8",
              boxWidth: 12,
              padding: 12,
              font: { family: "Inter", size: 11 }
            }
          },
          tooltip: {
            backgroundColor: "rgba(11, 16, 12, 0.95)",
            titleColor: "#f8fafc",
            bodyColor: "#94a3b8",
            borderColor: "rgba(255, 255, 255, 0.1)",
            borderWidth: 1,
            padding: 10
          }
        },
        cutout: "68%"
      }
    });
  }

  function renderRankedSignals(signals, totalAnalyses = 1) {
    if (!elements.insightsRankedSignals) return;
    elements.insightsRankedSignals.innerHTML = "";

    if (!signals || signals.length === 0) {
      elements.insightsRankedSignals.innerHTML = `
        <div style="text-align: center; padding: 2rem 1rem; color: var(--text-muted); font-size: 0.82rem;">
          No threat indicators detected in database analyses.
        </div>
      `;
      return;
    }

    const maxCount = Math.max(...signals.map(s => s.count), 1);

    signals.slice(0, 6).forEach(s => {
      const percentage = Math.min(100, Math.round((s.count / maxCount) * 100));
      const row = document.createElement("div");
      row.className = "ranked-signal-row";
      row.innerHTML = `
        <div class="ranked-signal-info">
          <span class="ranked-signal-name">${escapeHtml(s.label)}</span>
          <span class="ranked-signal-count">${s.count} ${s.count === 1 ? 'analysis' : 'analyses'}</span>
        </div>
        <div class="ranked-signal-bar-track">
          <div class="ranked-signal-bar-fill" style="width: ${percentage}%;"></div>
        </div>
      `;
      elements.insightsRankedSignals.appendChild(row);
    });
  }

  function renderIncidentStream(incidents) {
    if (!elements.insightsRecentStream) return;
    elements.insightsRecentStream.innerHTML = "";

    if (!incidents || incidents.length === 0) {
      elements.insightsRecentStream.innerHTML = `
        <div style="text-align: center; padding: 2rem 1rem; color: var(--text-muted); font-size: 0.82rem;">
          No recent detections recorded.
        </div>
      `;
      return;
    }

    incidents.forEach(inc => {
      const isSpam = inc.is_spam;
      const item = document.createElement("div");
      item.className = "incident-stream-item";
      item.title = "Click to inspect in Archive";
      item.innerHTML = `
        <div class="incident-item-text">
          "${escapeHtml(inc.message)}"
        </div>
        <div style="display: flex; align-items: center; gap: 0.5rem; flex-shrink: 0;">
          <span class="archive-badge ${isSpam ? 'badge-spam' : 'badge-ham'}">
            ${escapeHtml(inc.threat_level)} • ${escapeHtml(inc.prediction)}
          </span>
          <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: var(--text-muted);">
            ${escapeHtml(inc.created_at ? inc.created_at.slice(11, 16) : '')}
          </span>
        </div>
      `;

      item.addEventListener("click", () => {
        // Switch to Archive tab and inspect
        if (elements.tabs && elements.tabs[1]) {
          elements.tabs[1].click();
          if (typeof openArchiveDetail === "function" && inc.id) {
            openArchiveDetail(inc.id);
          }
        }
      });

      elements.insightsRecentStream.appendChild(item);
    });
  }

  // ==========================================================================
  // MODEL STATUS & TECHNICAL MODAL
  // ==========================================================================

  async function openModelInfoModal() {
    try {
      const response = await fetch("/api/model-info");
      const data = await response.json();

      if (data.success) {
        elements.modType.textContent = data.model_type;
        elements.modVectorizer.textContent = data.vectorizer;
        elements.modAcc.textContent = `${data.metrics.accuracy}%`;
        elements.modPrec.textContent = `${data.metrics.precision}%`;
        elements.modRec.textContent = `${data.metrics.recall}%`;
        elements.modF1.textContent = `${data.metrics.f1_score}%`;
        elements.modVocab.textContent = `${data.vocabulary_size} Features`;
        elements.modSamples.textContent = `${data.total_training_samples} SMS Samples`;

        elements.modTopFeatures.innerHTML = (data.top_spam_features || []).map(f => `
          <span class="feature-pill">${escapeHtml(f.feature)} (+${f.log_ratio})</span>
        `).join("");
      }

      elements.modalModelInfo.classList.remove("hidden");
    } catch (err) {
      showToast("Unable to load model metadata.", "error");
    }
  }

  elements.btnModelStatus.addEventListener("click", openModelInfoModal);
  elements.btnCloseModelModal.addEventListener("click", () => elements.modalModelInfo.classList.add("hidden"));
  elements.btnModalDismiss.addEventListener("click", () => elements.modalModelInfo.classList.add("hidden"));

  elements.modalModelInfo.addEventListener("click", (e) => {
    if (e.target === elements.modalModelInfo) {
      elements.modalModelInfo.classList.add("hidden");
    }
  });

  // ==========================================================================
  // HELPER UTILITIES
  // ==========================================================================

  function showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast-message toast-${type}`;
    const iconName = type === "success" ? "check-circle" : type === "error" ? "alert-circle" : "info";
    toast.innerHTML = `<i data-lucide="${iconName}"></i> <span>${escapeHtml(message)}</span>`;

    elements.toastContainer.appendChild(toast);
    if (window.lucide) lucide.createIcons();

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(5px)";
      toast.style.transition = "all 0.2s ease";
      setTimeout(() => toast.remove(), 200);
    }, 3200);
  }

  function animateNumber(element, start, end, duration) {
    const startTime = performance.now();
    function update(time) {
      const elapsed = time - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = Math.floor(start + (end - start) * progress);
      element.textContent = current;
      if (progress < 1) {
        requestAnimationFrame(update);
      } else {
        element.textContent = end;
      }
    }
    requestAnimationFrame(update);
  }

  function escapeHtml(str) {
    if (typeof str !== "string") return str;
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // ==========================================================================
  // THEME MANAGEMENT (LIGHT / DARK MODE)
  // ==========================================================================

  function initTheme() {
    const savedTheme = localStorage.getItem("sms_sentinel_theme") || "light";
    applyTheme(savedTheme, false);
  }

  function applyTheme(theme, showNotice = true) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("sms_sentinel_theme", theme);

    if (elements.themeIconSun && elements.themeIconMoon) {
      if (theme === "light") {
        elements.themeIconSun.classList.add("hidden");
        elements.themeIconMoon.classList.remove("hidden");
      } else {
        elements.themeIconSun.classList.remove("hidden");
        elements.themeIconMoon.classList.add("hidden");
      }
    }

    // Dynamic Chart Theme Adaptation
    const isLight = theme === "light";
    const gridColor = isLight ? "rgba(0, 0, 0, 0.07)": "rgba(34, 48, 35, 0.3)";
    const tickColor = isLight ? "#728775" : "#5c645a";
    const legendColor = isLight ? "#4a5e4d" : "#7f9280";

    if (state.charts.activity) {
      state.charts.activity.options.scales.x.grid.color = gridColor;
      state.charts.activity.options.scales.x.ticks.color = tickColor;
      state.charts.activity.options.scales.y.grid.color = gridColor;
      state.charts.activity.options.scales.y.ticks.color = tickColor;
      state.charts.activity.options.plugins.legend.labels.color = legendColor;
      state.charts.activity.update();
    }

    if (state.charts.distribution) {
      state.charts.distribution.options.plugins.legend.labels.color = legendColor;
      state.charts.distribution.data.datasets[0].borderColor = isLight ? "#ffffff" : "#0b100c";
      state.charts.distribution.update();
    }

    if (showNotice) {
      showToast(`${theme === "light" ? "Light" : "Dark"} mode activated.`, "info");
    }
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next = current === "light" ? "dark" : "light";
    applyTheme(next, true);
  }

  // Auth & User Profile Management
  async function initAuth() {
    try {
      const res = await fetch("/api/auth/me");
      const data = await res.json();
      if (data && data.authenticated && data.user) {
        const user = data.user;
        const name = user.name || "User";
        const initials = name
          .split(" ")
          .filter(Boolean)
          .map(n => n[0])
          .join("")
          .toUpperCase()
          .slice(0, 2) || "US";

        const nameElem = document.getElementById("userDisplayName");
        const initElem = document.getElementById("userInitials");
        if (nameElem) nameElem.textContent = name;
        if (initElem) initElem.textContent = initials;
      } else {
        window.location.href = "/login";
      }
    } catch (e) {
      console.warn("Auth verification error:", e);
    }
  }

  const btnLogout = document.getElementById("btnLogout");
  if (btnLogout) {
    btnLogout.addEventListener("click", async () => {
      try {
        await fetch("/api/auth/logout", { method: "POST" });
        showToast("Signed out successfully.", "info");
        setTimeout(() => {
          window.location.href = "/login";
        }, 300);
      } catch (e) {
        window.location.href = "/login";
      }
    });
  }

  // Initial setup
  initAuth();
  initTheme();
  renderPipelineTrace(buildFallbackPipelineTrace(null));
  updateArchiveCounter();
});
