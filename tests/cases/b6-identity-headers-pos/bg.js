// Synthetic shape (B6): request identity headers rewritten.
chrome.declarativeNetRequest.updateDynamicRules({
  removeRuleIds: [1],
  addRules: [{ id: 1, priority: 1, condition: { urlFilter: "|https://" },
    action: { type: "modifyHeaders", requestHeaders: [{ header: "user-agent", operation: "set", value: "x" }] } }]
});
