// Closest legitimate pattern: fromCharCode for ordinary text, URLs built from a base constant.
const greeting = String.fromCharCode(72, 101, 108, 108, 111);
const shifted = "abc".split("").map((c) => String.fromCharCode(c.charCodeAt(0) + 1)).join("");
const base = "https://api.example.com";
fetch(base + "/v1/items?q=" + encodeURIComponent(greeting + shifted));
