// Closest legitimate pattern: remote JSON configuration stored as data.
chrome.runtime.onStartup.addListener(async () => {
  const res = await fetch("https://cfg.example.invalid/settings.json");
  const settings = await res.json();
  await chrome.storage.local.set({ settings });
});
