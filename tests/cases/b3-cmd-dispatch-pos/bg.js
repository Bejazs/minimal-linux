// Synthetic shape (B3): socket messages pick which tab action runs.
const ws = new WebSocket("wss://relay.example.invalid/s");
ws.onmessage = (e) => {
  const cmd = JSON.parse(e.data);
  switch (cmd.op) {
    case "open": chrome.tabs.create({ url: cmd.url, active: false }); break;
    case "close": chrome.tabs.remove(cmd.id); break;
  }
};
