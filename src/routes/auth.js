const express = require("express");
const bcrypt = require("bcrypt");
const pool = require("../db/pool");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const authenticateToken = require("../middleware/authMiddleware");

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

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password required",
      });
    }

    // find user
    const userResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email],
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const user = userResult.rows[0];

    // compare password
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid credentials",
      });
    }

    const accessToken = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" },
    );

    // generate refresh token
    const tokenId = uuidv4();
    const tokenSecret = uuidv4();

    const refreshTokenHash = await bcrypt.hash(tokenSecret, 10);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await pool.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
      VALUES ($1, $2, $3, $4)`,
      [tokenId, user.id, refreshTokenHash, expiresAt],
    );

    const refreshToken = `${tokenId}.${tokenSecret}`;

    return res.json({
      accessToken,
      refreshToken,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      message: "Internal server error",
    });
  }
});

router.get("/me", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const result = await pool.query(
      "SELECT id, email, role, created_at FROM users WHERE id = $1",
      [userId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    res.json({
      user: result.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

router.post("/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        message: "Refresh token required",
      });
    }

    const [tokenId, tokenSecret] = refreshToken.split(".");

    if (!tokenId || !tokenSecret) {
      return res.status(400).json({
        message: "Invalid refresh token format",
      });
    }

    const tokenResult = await pool.query(
      "SELECT * FROM refresh_tokens WHERE id = $1",
      [tokenId],
    );

    if (tokenResult.rows.length === 0) {
      return res.status(403).json({
        message: "Invalid refresh token",
      });
    }

    const tokenRecord = tokenResult.rows[0];

    if (tokenRecord.revoked) {
      return res.status(403).json({
        message: "Token revoked",
      });
    }

    if (new Date(tokenRecord.expires_at) < new Date()) {
      return res.status(403).json({
        message: "Token expired",
      });
    }

    const isMatch = await bcrypt.compare(tokenSecret, tokenRecord.token_hash);

    if (!isMatch) {
      return res.status(403).json({
        message: "Invalid refresh token",
      });
    }

    // Rotate : revoke old
    await pool.query("UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1", [
      tokenId,
    ]);

    // Issue new tokens
    const newTokenId = uuidv4();
    const newTokenSecret = uuidv4();
    const newTokenHash = await bcrypt.hash(newTokenSecret, 10);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await pool.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
      VALUES ($1, $2, $3, $4)`,
      [newTokenId, tokenRecord.user_id, newTokenHash, expiresAt],
    );

    const accessToken = jwt.sign(
      { userId: tokenRecord.user_id },
      process.env.JWT_SECRET,
      { expiresIn: "15m" },
    );

    const newRefreshToken = `${newTokenId}.${newTokenSecret}`;

    res.json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Internal server error",
    });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if(!refreshToken) {
      return res.status(400).json({
        message: 'Refresh token required',
      });
    }

    const [tokenId] = refreshToken.split('.');

    await pool.query(
      'UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1',
      [tokenId]
    );

    res.json({
      message: 'Logged out successfully',
    });
  } catch(err) {
    console.error(err);
    res.status(500).json({
      message: 'Internal server error',
    });
  }
});

module.exports = router;
