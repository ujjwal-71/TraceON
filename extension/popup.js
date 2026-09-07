const BACKEND_URL = "http://127.0.0.1:8000";

document.addEventListener("DOMContentLoaded", () => {
    const shieldToggle = document.getElementById("shieldToggle");
    const shieldStatusText = document.getElementById("shieldStatusText");
    const fullSiteBtn = document.getElementById("fullSiteBtn");
    const uploadBtn = document.getElementById("uploadBtn");
    const fileInput = document.getElementById("fileInput");
    const dropArea = document.getElementById("dropArea");
    const scanStatus = document.getElementById("scanStatus");

    // Load saved shield state
    chrome.storage.local.get(["shieldActive"], (res) => {
        const active = res.shieldActive !== false;
        shieldToggle.checked = active;
        shieldStatusText.innerText = active ? "Shield ON" : "Shield OFF";
    });

    // Toggle switch handler
    shieldToggle.addEventListener("change", () => {
        const active = shieldToggle.checked;
        shieldStatusText.innerText = active ? "Shield ON" : "Shield OFF";
        chrome.storage.local.set({ shieldActive: active });
    });

    // Go to full site
    fullSiteBtn.addEventListener("click", () => {
        chrome.tabs.create({ url: BACKEND_URL });
    });

    // Middle round upload button
    uploadBtn.addEventListener("click", () => {
        fileInput.click();
    });

    fileInput.addEventListener("change", (e) => {
        const file = e.target.files[0];
        if (file) analyzeFile(file);
    });

    // Drag and drop on the round button
    dropArea.addEventListener("dragover", (e) => {
        e.preventDefault();
        uploadBtn.style.transform = "scale(1.08)";
    });

    dropArea.addEventListener("dragleave", () => {
        uploadBtn.style.transform = "scale(1)";
    });

    dropArea.addEventListener("drop", (e) => {
        e.preventDefault();
        uploadBtn.style.transform = "scale(1)";
        const file = e.dataTransfer.files[0];
        if (file) analyzeFile(file);
    });

    async function analyzeFile(file) {
        scanStatus.innerText = "Analyzing in volatile RAM...";
        scanStatus.style.color = "#06B6D4";

        const formData = new FormData();
        formData.append("file", file);

        try {
            const resp = await fetch(`${BACKEND_URL}/api/analyze`, {
                method: "POST",
                body: formData
            });
            const res = await resp.json();

            if (res.status === "success") {
                scanStatus.innerText = "Scan complete! Opening full studio...";
                scanStatus.style.color = "#10B981";
                chrome.tabs.create({ url: `${BACKEND_URL}/?case_id=${res.data.case_id}` });
            } else {
                scanStatus.innerText = "Scan failed: " + (res.detail || "Error");
                scanStatus.style.color = "#EF4444";
            }
        } catch (e) {
            scanStatus.innerText = "Connection error. Is TRACEON running?";
            scanStatus.style.color = "#EF4444";
        }
    }
});
