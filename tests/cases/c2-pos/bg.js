// Synthetic shape: periodic poll whose answer decides which tab to open.
setInterval(async () => {
  const r = await fetch("https://poll.example.invalid/next");
  const task = await r.json();
  chrome.tabs.create({ url: task.url, active: false });
}, 60000);
