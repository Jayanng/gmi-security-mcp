const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/read", (req, res) => {
  const name = path.basename(req.query.name);
  const p = path.join("/data", name);
  res.send(fs.readFileSync(p, "utf8"));
});
