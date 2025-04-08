require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Jamesmandi990",
    database: "bodycheck_database"
});

db.connect(err => {
    if (err) {
        console.error("Database connection error: " + err);
    } else {
        console.log("Connected to MySQL Database");
    }
});

// User Registration (Sign Up)
app.post("/signup", (req, res) => {
  const { name, email, password } = req.body; // No hashing

  db.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
      [name, email, password], 
      (err, result) => {
          if (err) return res.status(500).json({ error: err.message });
          res.json({ message: "User registered!" });
      }
  );
});


// User Login (Sign In)
app.post("/signin", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
      if (err) return res.status(500).json({ error: err.message });
      if (results.length === 0) return res.status(401).json({ error: "Invalid credentials" });

      const user = results[0];
      if (password !== user.password) { // Direct comparison
          return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign({ user_id: user.id }, "secretkey");
      res.json({ token });
  });
});


app.get("/profile", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "No token provided" });

  jwt.verify(token, "secretkey", (err, decoded) => {
      if (err) return res.status(401).json({ error: "Invalid token" });

      db.query("SELECT id, name, email FROM users WHERE id = ?", [decoded.user_id], (err, result) => {
          if (err) return res.status(500).json({ error: "Database error" });
          if (result.length === 0) return res.status(404).json({ error: "User not found" });

          res.json(result[0]); // Send user data
      });
  });
});
// Start Server
app.listen(3000, () => {
    console.log("Server running on port 3000");
});
