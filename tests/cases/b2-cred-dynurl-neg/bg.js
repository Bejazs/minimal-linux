// Closest legitimate pattern: credentialed call to the extension's own fixed endpoint.
fetch("https://api.example.com/me", { credentials: "include" }).then((r) => r.json());
