require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const User = require("./models/User");

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB

mongoose
  .connect(process.env.MONGODB_URI, { dbName: "ai-saas" })
  .then(() => console.log("MongDB connected!"))
  .catch((err) => console.error("MongoDB error: ", err));

// ─── MIDDLEWARE: Verify JWT token

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId; // attach userId to request
    req.userName = decoded.userName;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ─── ROUTE 1: Register

app.post("/auth/register", async (req, res) => {
  const { name, email, password } = req.body;

  if ((!name, !email, !password)) {
    return res.status(400).json({ error: "Name, email, password required" });
  }

  try {
    // Check if user already exists

    const existing = await User.findOne({ email });

    if (existing) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password — never store plain text
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    console.log(`New user registered: ${email}`);

    res.status(201).json({
      message: "Registration successful!",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ─── ROUTE 2: Login

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status.json(400).json({ error: "Email and password required" });
  }

  try {
    // Find user
    const user = await User.findOne({ email });

    if (!user) {
      return res.status.json({ error: "Invalid email or password" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status.json({ error: "Invalid email or password" });
    }

    // Create token

    const token = jwt.sign(
      { userId: user._id, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );
    console.log(`User logged in: ${email}`);

    res.json({
      message: "Login successful!",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ─── ROUTE 3: Get current user (protected route example)
app.get("/auth/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select("-password");
  res.json({
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      createdAt: user.createdAt,
    },
  });
});

const PORT = process.env.PORT || 7000;

app.listen(PORT, () => {
  console.log(`Auth server running on port ${PORT}`);
});
