const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db/pool");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

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

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email||!password) {
      return res.status(400).json({
        message: 'Email and password required',
      });
    }

    // find user
    const userResult = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [ email ]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        message: 'Invalid credentials',
      });
    }

    const user = userResult.rows[0];

    // compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        message: 'Invalid credentials',
      });
    }

    const accessToken = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // generate refresh token
    const refreshToken = uuidv4();

    const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)`,
      [user.id, refreshTokenHash, expiresAt]
    );

    return res.json({
      accessToken,
      refreshToken,
    });
  } catch(err) {
    console.error(err);
    return res.status(500).json({
      message: 'Internal server error',
    });
  }
});

module.exports = router;
