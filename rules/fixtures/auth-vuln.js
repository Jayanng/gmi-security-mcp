const express = require("express");
const app = express();

function getAdminData(req, res) {
  res.json({ users: loadAllUsers() });
}

// Public route, no auth needed: flagged by design, triage must judge it.
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/admin/users", getAdminData);

app.get("/admin/settings", (req, res) => {
  res.json(loadSettings());
});
