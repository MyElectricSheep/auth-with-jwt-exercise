const jwt = require("jsonwebtoken");

const authorizeUser = async (req, res, next) => {
  const { SECRET_KEY } = process.env;
  const authHeaders = req.headers.authorization;
  if (!authHeaders) return res.status(401).send("Access denied");

  const [_, token] = authHeaders.split(" ");
  if (!token) return res.status(401).send("Access denied");

  try {
    const payload = jwt.verify(token, SECRET_KEY);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(403).send("Invalid credentials");
  }
};

module.exports = authorizeUser;
