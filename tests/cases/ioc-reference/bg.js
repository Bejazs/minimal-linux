// Code-referenced: used by reachable code.
fetch("https://api.example.com/v1/items").then((r) => r.json());
// Data-only: in a function nothing calls, and in a prose string.
function unused() { return fetch("https://dead.example.net/x"); }
const help = "See https://docs.example.org/errors for details";
console.log(help);
