chrome.runtime.onMessage.addListener((msg, sender) => {
  chrome.windows.update(sender.tab.windowId, { focused: true, state: "maximized" });
});
