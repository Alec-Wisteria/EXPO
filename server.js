require("dotenv").config({ path: "./supabase.env" });
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// Enhanced CORS configuration
const allowedOrigins = [
  "http://localhost:3000",
  "https://your-vercel-app-url.vercel.app"
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Supabase client initialization with error handling
let supabase;
try {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY,
    {
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    }
  );
  console.log("Supabase client initialized successfully");
} catch (err) {
  console.error("Failed to initialize Supabase client:", err);
  process.exit(1);
}

// Enhanced User Registration
app.post("/signup", async (req, res) => {
  const { email, password, name } = req.body;

  // Input validation
  if (!email || !password || !name) {
    return res.status(400).json({ 
      error: "Missing required fields",
      details: {
        email: !email ? "Email is required" : null,
        password: !password ? "Password is required" : null,
        name: !name ? "Name is required" : null
      }
    });
  }

  // Email format validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  // Password strength validation
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  try {
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { name },
        emailRedirectTo: process.env.EMAIL_REDIRECT_URL || `${req.protocol}://${req.get('host')}/login`
      }
    });

    if (error) {
      console.error("Signup error:", error);
      return res.status(400).json({ 
        error: error.message,
        code: error.code 
      });
    }

    // Create user profile in your database if needed
    const { error: profileError } = await supabase
      .from('profiles')
      .insert([
        { 
          id: data.user.id,
          email: data.user.email,
          name: name,
          created_at: new Date().toISOString()
        }
      ]);

    if (profileError) {
      console.error("Profile creation error:", profileError);
      // Continue even if profile creation fails - auth was successful
    }

    res.json({ 
      message: "Registration successful! Please check your email to verify your account.",
      user: {
        id: data.user.id,
        email: data.user.email
      }
    });
  } catch (err) {
    console.error("Server error during signup:", err);
    res.status(500).json({ 
      error: "Internal server error",
      requestId: req.id
    });
  }
});

// Enhanced User Login
app.post("/signin", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ 
      error: "Missing credentials",
      details: {
        email: !email ? "Email is required" : null,
        password: !password ? "Password is required" : null
      }
    });
  }

  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });

    if (error) {
      console.error("Login error:", error);
      return res.status(401).json({ 
        error: "Invalid credentials",
        details: error.message
      });
    }

    res.json({
      token: data.session.access_token,
      refresh_token: data.session.refresh_token,
      user: {
        id: data.user.id,
        email: data.user.email,
        name: data.user.user_metadata?.name
      }
    });
  } catch (err) {
    console.error("Server error during login:", err);
    res.status(500).json({ 
      error: "Internal server error",
      requestId: req.id
    });
  }
});

// Protected Profile Route
app.get("/profile", async (req, res) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ 
      error: "Authorization token required",
      hint: "Format: 'Bearer <token>'"
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error) {
      console.error("Token verification error:", error);
      return res.status(401).json({ 
        error: "Invalid or expired token",
        details: error.message
      });
    }

    // Optional: Fetch additional user data from your database
    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select('*')
      .eq('id', user.id)
      .single();

    res.json({
      id: user.id,
      email: user.email,
      name: user.user_metadata?.name || profile?.name,
      // Include other profile fields as needed
      ...(profile || {})
    });
  } catch (err) {
    console.error("Server error during profile fetch:", err);
    res.status(500).json({ 
      error: "Internal server error",
      requestId: req.id
    });
  }
});

// Health Check Endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ 
    status: "OK",
    timestamp: new Date().toISOString(),
    supabase: supabase ? "Connected" : "Disconnected"
  });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ 
    error: "Internal server error",
    message: err.message
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Supabase URL: ${process.env.SUPABASE_URL}`);
});
