const box = document.getElementById("note");
chrome.storage.local.get("note").then((v) => { box.value = v.note || ""; });
box.addEventListener("change", () => chrome.storage.local.set({ note: box.value }));
