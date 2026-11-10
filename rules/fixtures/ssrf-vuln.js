const express = require("express");
const app = express();

app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  const response = await fetch(url);
  res.send(await response.text());
});
