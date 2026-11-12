// Open prefix test before a privileged action.
chrome.runtime.onMessageExternal.addListener((msg, sender) => {
  if (!sender.url.startsWith("https://app.example.com")) return;
  chrome.tabs.create({ url: msg.url });
});
