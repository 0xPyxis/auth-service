const bcrypt = require("bcrypt");
const pool = require("../db/pool");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

async function login({ email, password }) {
  if (!email || !password) {
    throw { status: 400, message: "Email and password required" };
  }

  const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);

  if (userResult.rows.length === 0) {
    throw { status: 401, message: "Invalid credentials" };
  }

  const user = userResult.rows[0];

  if (user.lock_until && new Date(user.lock_until) > new Date()) {
    throw { status: 403, message: "Account temporarily locked" };
  }

  const isMatch = await bcrypt.compare(password, user.password_hash);

  if (!isMatch) {
    const failedAttempts = user.failed_attempts + 1;
    if (failedAttempts >= 5) {
      const lockUntil = new Date();
      lockUntil.setMinutes(lockUntil.getMinutes + 5);

      await pool.query(
        `UPDATE users
            SET failed_attempts=0
            lock_until = $1
            WHERE id=$2`,
        [lockUntil, user.id],
      );

      throw { status: 403, message: "Account locked for 5 minutes" };
    }

    // reset lock counters
    await pool.query(
      `UPDATE users SET failed_attempts=0,
        lock_until=NULL 
        WHERE id=$1`,
      [user.id],
    );

    const accessToken = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" },
    );

    const tokenId = uuidv4();
    const tokenSecret = uuidv4();
    const refreshTokenHash = await bcrypt.hash(tokenSecret, 10);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await pool.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
        VALUES ($1, $2,$3,$4)`,
      [tokenId, user.id, refreshTokenHash, expiresAt],
    );

    const refreshToken = `${tokenId}.${tokenSecret}`;

    return { accessToken, refreshToken };
  }
}

module.exports = {
  login,
};
