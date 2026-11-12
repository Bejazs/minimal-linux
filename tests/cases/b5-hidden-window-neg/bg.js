// Closest legitimate pattern: a normal-size popup window.
chrome.action.onClicked.addListener(() => {
  chrome.windows.create({ url: "panel.html", type: "popup", width: 400, height: 600 });
});
