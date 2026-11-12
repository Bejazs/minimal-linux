// Exact allow-list.
const ALLOWED = ["https://app.example.com"];
chrome.runtime.onMessageExternal.addListener((msg, sender) => {
  if (!ALLOWED.includes(sender.origin)) return;
  if (!sender.url.startsWith("https://app.example.com/")) return;
  chrome.tabs.create({ url: "https://app.example.com/help" });
});
