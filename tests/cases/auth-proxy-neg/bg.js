// Closest legitimate pattern: credentialed call to the extension's own fixed API.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  fetch("https://api.example.com/me", { credentials: "include" }).then((r) => r.json()).then(reply);
  return true;
});
