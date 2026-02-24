const pool = require("../db/pool");

function startTokenCleanup() {
  setInterval(
    async () => {
      try {
        const result = await pool.query(
          "DELETE FROM refresh_tokens WHERE expires_at < NOW()",
        );

        if (result.rowCount > 0) {
          console.log(`Cleaned ${result.rowCount} expired tokens`);
        }
      } catch (err) {
        console.error("Token cleanup error : ", err);
      }
    },
    60 * 60 * 1000,
  ); // every hour
}

module.exports = startTokenCleanup;
