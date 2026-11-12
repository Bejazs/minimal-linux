// Closest legitimate pattern: periodic config poll whose values are only stored as data.
setInterval(async () => {
  const cfg = await (await fetch("https://api.example.com/config")).json();
  switch (cfg.theme) {
    case "dark": chrome.storage.local.set({ theme: "dark" }); break;
    default: chrome.storage.local.set({ theme: "light" });
  }
}, 3600000);
