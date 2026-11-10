const express = require("express");
const app = express();

function validateUrl(raw) {
  const parsed = new URL(raw);
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    throw new Error("host not allowed");
  }
  return parsed.toString();
}

app.get("/proxy", async (req, res) => {
  const url = validateUrl(req.query.url);
  const response = await fetch(url);
  res.send(await response.text());
});
