// Closest legitimate pattern: a non-identity header added for the extension's own API.
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [{ id: 1, priority: 1, condition: { urlFilter: "||api.example.com" },
    action: { type: "modifyHeaders", requestHeaders: [{ header: "x-client-version", operation: "set", value: "1.0" }] } }]
});
