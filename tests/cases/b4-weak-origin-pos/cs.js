// Synthetic shape (B4): substring origin test in a window message handler.
window.addEventListener("message", (e) => {
  if (e.origin.indexOf("example.com") === -1) return;
  chrome.runtime.sendMessage({ op: e.data.op });
});
