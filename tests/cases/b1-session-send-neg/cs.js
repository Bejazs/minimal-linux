// Closest legitimate pattern: settings synced to the extension's own declared API.
const prefs = { s: localStorage.getItem("prefs") };
fetch("https://api.example.com/sync", { method: "POST", body: JSON.stringify(prefs) });
