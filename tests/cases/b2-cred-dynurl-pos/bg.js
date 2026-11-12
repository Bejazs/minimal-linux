// Synthetic shape (B2): the URL for a credentialed request comes from a message.
chrome.runtime.onMessage.addListener((msg) => {
  fetch(msg.target, { credentials: "include" }).then((r) => r.status);
});
const xhr = new XMLHttpRequest();
chrome.storage.local.get("next", (st) => {
  xhr.open("GET", st.next);
  xhr.withCredentials = true;
  xhr.send();
});
