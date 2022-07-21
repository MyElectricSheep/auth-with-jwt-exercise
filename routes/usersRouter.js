const express = require("express");
const router = express.Router();
const db = require("../database/client");
const bcrypt = require("bcrypt");

router.post("/", async (req, res, next) => {
  const { name, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const createOneUser = {
      text: `
      INSERT INTO users
      (name, password, created_on)
      VALUES ($1, $2, now())
      RETURNING *`,
      values: [name, hashedPassword],
    };
    const data = await db.query(createOneUser);
    res.status(201).json(data.rows);
  } catch (error) {
    next(error);
  }
});

module.exports = router;
