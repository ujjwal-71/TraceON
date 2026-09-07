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
    // 1. In Gmail Row List (Next to Star / Important marker)
    const rows = document.querySelectorAll("tr.zA:not(.traceon-injected)");
    rows.forEach(row => {
        row.classList.add("traceon-injected");
        const starOrImportantCell = row.querySelector("td.apU, td.yX, .T-KT, .pG");
        if (starOrImportantCell) {
            const btn = document.createElement("button");
            btn.className = "traceon-gmail-scan-btn";
            btn.title = "TRACEON 1-Click Forensic Scan";
            btn.innerHTML = `<span class="traceon-shield-icon">🛡️</span><span class="traceon-btn-tag">TRACEON</span>`;
            
            btn.addEventListener("click", (e) => {
                e.stopPropagation();
                e.preventDefault();
                scanGmailRow(row);
            });

            starOrImportantCell.appendChild(btn);
        }
    });

    // 2. Inside Open Email View Toolbar
    const toolbars = document.querySelectorAll(".G-Ni.J-J5-Ji:not(.traceon-toolbar-injected)");
    toolbars.forEach(toolbar => {
        toolbar.classList.add("traceon-toolbar-injected");
        const btn = document.createElement("button");
        btn.className = "traceon-toolbar-btn";
        btn.innerHTML = `🛡️ <span>TRACEON Scan</span>`;
        btn.title = "Execute Ephemeral AI Forensic Scan";
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            e.preventDefault();
            scanOpenEmail();
        });
        toolbar.appendChild(btn);
    });
}

function injectOutlookButtons() {
    const outlookRows = document.querySelectorAll("[data-convid]:not(.traceon-injected)");
    outlookRows.forEach(row => {
        row.classList.add("traceon-injected");
        const btn = document.createElement("button");
        btn.className = "traceon-gmail-scan-btn";
        btn.innerHTML = `🛡️ TRACEON`;
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            e.preventDefault();
            scanGenericDom(row);
        });
        row.appendChild(btn);
    });
}

function scanGmailRow(row) {
    const sender = row.querySelector(".yP, .zF, span[email]")?.innerText || "Unknown Sender";
    const subject = row.querySelector(".bog, .bqe")?.innerText || "(No Subject)";
    const snippet = row.querySelector(".y2")?.innerText || "";

    const rawEmail = `From: ${sender}
Subject: ${subject}
Date: ${new Date().toUTCString()}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

${snippet}
`;
    executeScanAndShowModal(rawEmail, subject, sender);
}

function scanOpenEmail() {
    const subject = document.querySelector("h2.hP")?.innerText || "(No Subject)";
    const sender = document.querySelector("span.gD")?.innerText || document.querySelector("span[email]")?.innerText || "Unknown";
    const body = document.querySelector(".a3s.aiL, .adn.ads")?.innerText || "";

    const rawEmail = `From: ${sender}
Subject: ${subject}
Date: ${new Date().toUTCString()}
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
