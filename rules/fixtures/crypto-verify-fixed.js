const jwt = require("jsonwebtoken");

function verifyToken(token, key) {
  return jwt.verify(token, key, { algorithms: ["HS256"] });
}
