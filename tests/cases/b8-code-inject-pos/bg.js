// Synthetic shape (B8): code string from a message injected into a tab.
chrome.runtime.onMessage.addListener((msg, sender) => {
  chrome.tabs.executeScript(sender.tab.id, { code: msg.code });
});
