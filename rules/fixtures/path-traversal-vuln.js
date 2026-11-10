const express = require("express");
const fs = require("fs");
const path = require("path");
const app = express();

app.get("/read", (req, res) => {
  const p = path.join("/data", req.query.name);
  res.send(fs.readFileSync(p, "utf8"));
});
