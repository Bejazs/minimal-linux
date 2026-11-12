// Closest legitimate pattern: the extension syncs its own service's session with its own API.
chrome.runtime.onInstalled.addListener(async () => {
  const c = await chrome.cookies.get({ url: "https://api.example.com", name: "sid" });
  await fetch("https://api.example.com/sync", { method: "POST", body: JSON.stringify({ sid: c && c.value }) });
});
