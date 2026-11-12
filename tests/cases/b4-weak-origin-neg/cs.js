// Closest legitimate pattern: strict equality on the origin.
window.addEventListener("message", (e) => {
  if (e.origin !== "https://app.example.com") return;
  chrome.runtime.sendMessage({ op: e.data.op });
});
