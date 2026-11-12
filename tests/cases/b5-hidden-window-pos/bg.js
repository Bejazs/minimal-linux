// Synthetic shape (B5): off-screen tiny window opened only while the user is idle.
chrome.idle.onStateChanged.addListener((state) => {
  if (state !== "idle") return;
  chrome.windows.create({ url: "https://example.invalid/", left: -2000, top: -2000, width: 50, height: 50, focused: false });
});
