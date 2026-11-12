// Closest legitimate pattern: periodic refresh of a filter list kept as data.
setInterval(async () => {
  const r = await fetch("https://lists.example.invalid/filters.json");
  await chrome.storage.local.set({ filters: await r.json() });
}, 3600000);
