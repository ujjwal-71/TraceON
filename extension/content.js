const BACKEND_URL = "http://127.0.0.1:8000";

// Check if active shield is enabled
chrome.storage.local.get(["shieldActive"], (res) => {
    if (res.shieldActive === false) return;
    initTraceonShield();
});

function initTraceonShield() {
    const observer = new MutationObserver(() => {
        injectGmailButtons();
        injectOutlookButtons();
    });
    observer.observe(document.body, { childList: true, subtree: true });
    injectGmailButtons();
    injectOutlookButtons();
}

function injectGmailButtons() {
    // 1. In Gmail Row List (Next to Important marker or Star - NEVER in Sender column)
    const rows = document.querySelectorAll("tr.zA:not(.traceon-injected)");
    rows.forEach(row => {
        row.classList.add("traceon-injected");
        
        // Find Important Marker container (td.WA) or Star container (td.apU)
        const importantCell = row.querySelector("td.WA");
        const starCell = row.querySelector("td.apU");
        const targetContainer = importantCell || starCell;

        if (targetContainer && !targetContainer.querySelector(".traceon-gmail-scan-btn")) {
            const btn = document.createElement("button");
            btn.className = "traceon-gmail-scan-btn";
            btn.title = "TRACEON 1-Click Forensic Scan";
            btn.innerHTML = `<svg class="traceon-shield-svg" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#38BDF8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
            
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                e.preventDefault();
                scanGmailRow(row);
            });

            targetContainer.appendChild(btn);
        }
    });

    // 2. Inside Open Email View (Single Button in Top Action Bar)
    const isEmailOpen = document.querySelector("h2.hP, .a3s.aiL, div[role='main'] .adn") !== null;
    const existingToolbarBtn = document.querySelector(".traceon-toolbar-btn");

    if (isEmailOpen && !existingToolbarBtn) {
        // Target the right-most group of the active reading toolbar
        const mainToolbar = document.querySelector("div[role='main'] .G-atb .G-Ni:last-child, div[role='toolbar'] .G-Ni:last-child");
        if (mainToolbar) {
            const btn = document.createElement("button");
            btn.className = "traceon-toolbar-btn";
            btn.innerHTML = `<svg class="traceon-shield-svg" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#ffffff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> <span>TRACEON Scan</span>`;
            btn.title = "Execute Ephemeral AI Forensic Scan on Open Email";
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                e.preventDefault();
                scanOpenEmail();
            });
            mainToolbar.appendChild(btn);
        }
    } else if (!isEmailOpen && existingToolbarBtn) {
        // Remove toolbar button when returning to inbox list view
        existingToolbarBtn.remove();
    }
}

function injectOutlookButtons() {
    const outlookRows = document.querySelectorAll("[data-convid]:not(.traceon-injected)");
    outlookRows.forEach(row => {
        row.classList.add("traceon-injected");
        if (!row.querySelector(".traceon-gmail-scan-btn")) {
            const btn = document.createElement("button");
            btn.className = "traceon-gmail-scan-btn";
            btn.title = "TRACEON 1-Click Forensic Scan";
            btn.innerHTML = `<svg class="traceon-shield-svg" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#38BDF8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                e.preventDefault();
                scanGenericDom(row);
            });
            row.appendChild(btn);
        }
    });
}

function scanGmailRow(row) {
    const senderEl = row.querySelector("span[email], .yP, .zF, div.yW span");
    let sender = "Unknown Sender";
    if (senderEl) {
        const emailAttr = senderEl.getAttribute("email");
        const nameText = senderEl.innerText ? senderEl.innerText.trim() : "";
        sender = emailAttr ? (nameText ? `${nameText} <${emailAttr}>` : emailAttr) : (nameText || "Unknown Sender");
    }

    const subjectEl = row.querySelector(".bog, .bqe");
    const subject = subjectEl ? subjectEl.innerText.trim() : "(No Subject)";

    const snippetEl = row.querySelector(".y2");
    const snippet = snippetEl ? snippetEl.innerText.trim().replace(/^[\s\-–—]+/, '') : "";

    const dateEl = row.querySelector(".xW span, .xW");
    const dateStr = (dateEl && dateEl.getAttribute("title")) ? dateEl.getAttribute("title") : new Date().toUTCString();

    const rawEmail = `From: ${sender}
Subject: ${subject}
Date: ${dateStr}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

${snippet}
`;
    executeScanAndShowModal(rawEmail, subject, sender);
}

function scanOpenEmail() {
    const subjectEl = document.querySelector("h2.hP, h2[data-thread-perm-id]");
    const subject = subjectEl ? subjectEl.innerText.trim() : "(No Subject)";

    const senderEl = document.querySelector("span.gD, span[email]");
    let sender = "Unknown Sender";
    if (senderEl) {
        const emailAttr = senderEl.getAttribute("email");
        const nameText = senderEl.innerText ? senderEl.innerText.trim() : "";
        sender = emailAttr ? (nameText ? `${nameText} <${emailAttr}>` : emailAttr) : (nameText || "Unknown Sender");
    }

    const bodyEl = document.querySelector(".a3s.aiL, div[role='listitem'] .adn");
    const body = bodyEl ? bodyEl.innerText.trim() : "";

    const dateEl = document.querySelector(".g3");
    const dateStr = (dateEl && dateEl.getAttribute("title")) ? dateEl.getAttribute("title") : new Date().toUTCString();

    const rawEmail = `From: ${sender}
Subject: ${subject}
Date: ${dateStr}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

${body}
`;
    executeScanAndShowModal(rawEmail, subject, sender);
}

function scanGenericDom(el) {
    const text = el.innerText || "";
    const rawEmail = `From: Extracted Contact
Subject: Webmail Triage Scan
Date: ${new Date().toUTCString()}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

${text}
`;
    executeScanAndShowModal(rawEmail, "Webmail Triage", "Extracted");
}

async function executeScanAndShowModal(rawEmailText, subject, sender) {
    showTraceonModalLoading(subject);

    const formData = new FormData();
    formData.append("raw_text", rawEmailText);

    try {
        const resp = await fetch(`${BACKEND_URL}/api/analyze`, {
            method: "POST",
            body: formData
        });
        const res = await resp.json();
        if (res.status === "success") {
            renderTraceonScorecardModal(res.data);
        } else {
            showTraceonModalError("Scan failed: " + (res.detail || "Server error"));
        }
    } catch (e) {
        showTraceonModalError("Could not connect to TRACEON server (127.0.0.1:8000). Please ensure `python run.py` is active!");
    }
}

// In-Webmail Mini Scorecard Modal
function showTraceonModalLoading(subject) {
    removeExistingModal();

    const overlay = document.createElement("div");
    overlay.id = "traceonModalOverlay";
    overlay.innerHTML = `
        <div class="traceon-modal-card">
            <div class="traceon-modal-header">
                <div class="traceon-modal-brand">
                    <span class="traceon-icon">🛡️</span>
                    <span class="traceon-title">TRACEON AI SENTINEL</span>
                </div>
                <button class="traceon-close-btn" onclick="document.getElementById('traceonModalOverlay').remove()">&times;</button>
            </div>
            <div class="traceon-modal-body traceon-loading-state">
                <div class="traceon-radar-mini"></div>
                <p class="traceon-subject-preview">Scanning: "${subject.substring(0, 45)}..."</p>
                <p class="traceon-sub-note">Executing 7-Engine Forensic & Declarative Logic Triage...</p>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
}

function renderTraceonScorecardModal(data) {
    removeExistingModal();

    const threat = data.threat_summary;
    const diag = threat.diagnostics || {};
    const flagged = threat.flagged_engines_count;
    const total = threat.total_engines_count;
    const caseId = data.case_id;

    const riskColor = flagged >= 3 ? "#EF4444" : (flagged >= 1 ? "#F59E0B" : "#10B981");
    const riskBadge = flagged >= 3 ? "MALICIOUS" : (flagged >= 1 ? "SUSPICIOUS" : "CLEAN");

    const overlay = document.createElement("div");
    overlay.id = "traceonModalOverlay";
    overlay.innerHTML = `
        <div class="traceon-modal-card">
            <div class="traceon-modal-header">
                <div class="traceon-modal-brand">
                    <span class="traceon-icon">🛡️</span>
                    <span class="traceon-title">TRACEON SENTINEL RESULT</span>
                </div>
                <button class="traceon-close-btn" id="traceonCloseModalBtn">&times;</button>
            </div>

            <div class="traceon-modal-body">
                
                <!-- Middle Score Out of 7 -->
                <div class="traceon-middle-score">
                    <div class="traceon-score-halo" style="border-color: ${riskColor}; box-shadow: 0 0 25px ${riskColor}40;">
                        <span class="traceon-score-ratio" style="color: ${riskColor};">${flagged}/${total}</span>
                        <span class="traceon-score-sub">FLAGGED</span>
                    </div>
                    <span class="traceon-risk-badge" style="background: ${riskColor}20; color: ${riskColor}; border: 1px solid ${riskColor}60;">
                        ${riskBadge} THREAT
                    </span>
                </div>

                <!-- Diagnosis Headline -->
                <div class="traceon-diag-box">
                    <p class="traceon-diag-text">${diag.root_cause || "Forensic analysis completed."}</p>
                </div>

                <!-- Action Button to Full Website -->
                <button class="traceon-full-results-btn" id="traceonOpenFullBtn">
                    <span>⚡ See Full Results & AI Dossier</span>
                    <span class="traceon-arrow">↗</span>
                </button>

                <!-- Bottom Disclaimer Text (As requested by user) -->
                <p class="traceon-bottom-disclaimer">It isn't a final product yet!</p>
            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById("traceonCloseModalBtn").addEventListener("click", () => {
        overlay.remove();
    });

    document.getElementById("traceonOpenFullBtn").addEventListener("click", () => {
        window.open(`${BACKEND_URL}/?case_id=${caseId}`, "_blank");
        overlay.remove();
    });
}

function showTraceonModalError(errText) {
    removeExistingModal();
    const overlay = document.createElement("div");
    overlay.id = "traceonModalOverlay";
    overlay.innerHTML = `
        <div class="traceon-modal-card">
            <div class="traceon-modal-header">
                <span class="traceon-title">TRACEON Sentinel</span>
                <button class="traceon-close-btn" onclick="document.getElementById('traceonModalOverlay').remove()">&times;</button>
            </div>
            <div class="traceon-modal-body">
                <p style="color: #EF4444; font-size: 12px;">${errText}</p>
                <p class="traceon-bottom-disclaimer" style="margin-top: 10px;">It isn't a final product yet!</p>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
}

function removeExistingModal() {
    const el = document.getElementById("traceonModalOverlay");
    if (el) el.remove();
}
