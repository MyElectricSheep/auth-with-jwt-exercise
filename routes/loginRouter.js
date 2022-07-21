const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const db = require("../database/client");
const bcrypt = require("bcrypt");
const path = require("path");
const authorizeUser = require("../middlewares/authorizeUser");

const publicFilesPath = path.join(__dirname, "../", "public");
const protectedFilesPath = path.join(__dirname, "../", "protected");

router.get("/login", (req, res) => {
  res.sendFile(path.join(publicFilesPath, "login.html"));
});

router.post("/connect", (req, res) => {
  const { username, password } = req.body;
  const { FAKE_USERNAME, FAKE_PASSWORD } = process.env;

  if (username === FAKE_USERNAME && password === FAKE_PASSWORD) {
    const payload = { username, admin: true };
    const secretKey = process.env.SECRET_KEY;
    const token = jwt.sign(payload, secretKey);
    res
      .set("x-authorization-token", token)
      .sendFile(path.join(publicFilesPath, "checkToken.html"));
  } else {
    res.redirect("/");
  }
});

router.post("/connectSQL", async (req, res) => {
  const { username, password } = req.body;
  const { SECRET_KEY } = process.env;

  try {
    const findUser = {
      text: `
      SELECT * 
      FROM users
      WHERE name = $1`,
      values: [username],
    };
    const data = await db.query(findUser);

    if (!data.rows.length) {
      return res.redirect("/");
    }

    const { id, name, admin, password: dbPassword } = data.rows[0];

    const match = await bcrypt.compare(password, dbPassword);

    if (match) {
      const payload = { name, id, admin };
      const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
      res
        .set("x-authorization-token", token)
        .sendFile(path.join(publicFilesPath, "checkToken.html"));
    } else {
      res.redirect("/");
    }
  } catch (error) {
    next(error);
  }
});

router.post("/checkJWT", (req, res) => {
  const { token } = req.body;
  const { SECRET_KEY } = process.env;
  try {
    const payload = jwt.verify(token, SECRET_KEY);

    if (payload && payload.admin) {
      res.redirect("admin");
    } else {
      res.redirect("/");
    }
  } catch (e) {
    console.log(e.message);
    res.redirect("/");
  }
});

router.get("/admin", (req, res) => {
  const previousRoute = req.header("Referer") || "/";
  if (!previousRoute.includes("/jwt/connect")) {
    return res.redirect("/");
  }
  res.sendFile(path.join(protectedFilesPath, "admin.html"));
});

router.get("/restricted", authorizeUser, (req, res) => {
  res.send("Welcome to the protected area");
});

module.exports = router;
