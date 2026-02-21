const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db/pool");

const router = express.Router();

router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    // basic validation
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    // password hashing
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // insert into DB
    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
            VALUES ($1, $2)
            RETURNING id, email, role, created_at`,
      [email, passwordHash],
    );

    return res.status(201).json({
      message: "User registered successfully",
      user: result.rows[0],
    });
  } catch (err) {
    if (err.code == "23505") {
      return res.status(409).json({
        message: "Email already exists",
      });
    }

    console.error(err);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

module.exports = router;
