require("dotenv").config(); // loads environment variables from a .env file.

const express = require("express"); // Express wraps Node’s HTTP module and makes routing easy.
const pool = require("./db/pool");
const authRoutes = require("./routes/auth");
const PORT = process.env.PORT || 5000; // if port is specified in env file use it, else use default one as 5000
const errorHandler = require("./middleware/errorHandler");
const helmet = require("helmet");
const cors = require("cors");

const app = express(); // creates the main server instance
app.use(helmet());

app.use(
  cors({
    origin: "http://localhost:3000", // frontend
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  }),
);

app.use(express.json()); // This is middleware. It parses incoming JSON bodies and puts them inside: req.body

app.get("/health", (req, res) => {
  // This is a health check endpoint. In prod, balancers etc ping this to check health of our server.
  res.status(200).json({ status: "OK" });
});

async function validateDB() {
  try {
    await pool.query('SELECT 1');
    console.log("Database connected");
  } catch(err) {
    console.error('Database connection failed');
    process.exit(1);
  }
}

app.use("/auth", authRoutes);

app.use(errorHandler);

const startTokenCleanup = require("./utils/tokenCleanup");
startTokenCleanup();

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
