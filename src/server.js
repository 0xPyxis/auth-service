require("dotenv").config(); // loads environment variables from a .env file.

const express = require("express"); // Express wraps Node’s HTTP module and makes routing easy.
const pool = require("./db/pool");
const authRoutes = require('./routes/auth');
const PORT = process.env.PORT || 5000; // if port is specified in env file use it, else use default one as 5000

const app = express(); // creates the main server instance

app.use(express.json()); // This is middleware. It parses incoming JSON bodies and puts them inside: req.body

app.get("/health", (req, res) => {
  // This is a health check endpoint. In prod, balancers etc ping this to check health of our server.
  res.status(200).json({ status: "OK" });
});

pool
  .query("SELECT current_database()")
  .then((res) => {
    console.log("DB connected:", res.rows[0]);
  })
  .catch((err) => {
    console.error("DB connection error:", err);
  });

app.use('/auth',authRoutes);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
