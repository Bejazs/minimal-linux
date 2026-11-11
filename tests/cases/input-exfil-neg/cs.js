// Closest legitimate pattern: a shortcut handler that messages its own background page.
document.addEventListener("keydown", (ev) => {
  if (ev.altKey && ev.key === "s") chrome.runtime.sendMessage({ cmd: "save" });
});
