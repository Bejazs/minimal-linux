// Closest legitimate pattern: packaged function and packaged file injected.
function highlight(color) { document.body.style.background = color; }
chrome.action.onClicked.addListener((tab) => {
  chrome.scripting.executeScript({ target: { tabId: tab.id }, func: highlight, args: ["yellow"] });
  chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
});
