// Background service worker
chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({ shieldActive: true });
});
