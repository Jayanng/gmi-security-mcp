const express = require("express");
const app = express();

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "unauthorised" });
  }
  return next();
}

function getAdminData(req, res) {
  res.json({ users: loadAllUsers() });
}

app.get("/admin/users", requireAuth, getAdminData);

app.get("/admin/settings", requireAuth, (req, res) => {
  res.json(loadSettings());
});
