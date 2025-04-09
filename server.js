require("dotenv").config({ path: "./supabase.env" });
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.use(cors({ origin: "*" })); // Allow all origins (for development only)
app.use(bodyParser.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// User Registration (Sign Up)
app.post("/signup", async (req, res) => {
    const { email, password, name } = req.body;
  
    // Validate input
    if (!email || !password || !name) {
      return res.status(400).json({ error: "Missing required fields" });
    }
  
    try {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: { name },
        },
      });
  
      if (error) {
        return res.status(400).json({ error: error.message });
      }
  
      res.json({ message: "User registered! Please check your email to confirm", user: data.user });
    } catch (err) {
      console.error("Error during signup:", err);
      res.status(500).json({ error: "Something went wrong during sign-up" });
    }
  });
  

// User Login (Sign In)
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  const { data, error } = await supabase.auth.signInWithPassword({
    email,
    password
  });

  if (error) return res.status(401).json({ error: error.message });

  const token = data.session?.access_token;

  res.json({ token });
});

// Profile Route
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "No token provided" });

  const {
    data: { user },
    error
  } = await supabase.auth.getUser(token);

  if (error) return res.status(401).json({ error: error.message });

  res.json({
    id: user.id,
    email: user.email,
    name: user.user_metadata?.name || "No name"
  });
});

// Start Server
app.listen(3000, () => {
  console.log("Server running on port 3000 with Supabase");
});
