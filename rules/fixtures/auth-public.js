const express = require("express");
const app = express();

// Public route, no auth needed. The rule flags it by design:
// it cannot tell a public route from an unprotected admin route.
// Triage must judge whether the route needs auth.
app.get("/health", (req, res) => {
  res.json({ ok: true });
});
