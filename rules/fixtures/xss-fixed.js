const express = require("express");
const app = express();

function escape(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

app.get("/hello", (req, res) => {
  res.send("<h1>Hello " + escape(req.query.name) + "</h1>");
});
