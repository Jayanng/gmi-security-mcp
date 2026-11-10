const jwt = require("jsonwebtoken");

function decodeToken(token) {
  return jwt.decode(token);
}

function verifyLoose(token, key) {
  return jwt.verify(token, key, { ignoreExpiration: true });
}
