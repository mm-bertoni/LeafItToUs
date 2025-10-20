import express from "express";
import bcrypt from "bcrypt";
import { ObjectId } from "mongodb";
import { getCollection } from "../config/database.js";

const router = express.Router();

// Sign up
router.post("/signup", async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const users = getCollection("users");

    // Check if user exists
    const existingUser = await users.findOne({ username });
    if (existingUser) {
      return res.status(409).json({ error: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await users.insertOne({
      username,
      email,
      password: hashedPassword,
      bio: "",
      createdAt: new Date(),
    });

    // Store all user info in session
    req.session.userId = result.insertedId.toString();
    req.session.username = username;
    req.session.email = email;
    req.session.bio = "";

    res.status(201).json({
      message: "User created successfully",
      userId: result.insertedId,
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const users = getCollection("users");
    const user = await users.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Would be helpful to provide some comments on how bcrypt works since it's a package we haven't used yet in the class. 
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Store all user info in session
    req.session.userId = user._id.toString();
    req.session.username = user.username;
    req.session.email = user.email || "";
    req.session.bio = user.bio || "";

    res.json({
      message: "Login successful",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        bio: user.bio || "",
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

// Logout
router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Could not logout" });
    }
    res.json({ message: "Logout successful" });
  });
});

// Get current user
router.get("/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  res.json({
    userId: req.session.userId,
    username: req.session.username,
    email: req.session.email || "",
    bio: req.session.bio || "",
  });
});

// Update profile
router.put("/profile", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const { email, bio } = req.body;
    const users = getCollection("users");

    const result = await users.updateOne(
      { _id: new ObjectId(req.session.userId) },
      { $set: { email, bio, updatedAt: new Date() } },
    );
    console.log(result);

    if (email !== undefined) req.session.email = email;
    if (bio !== undefined) req.session.bio = bio;

    res.json({ message: "Profile updated successfully" });
  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ error: "Server error" });
  }
});

export default router;
