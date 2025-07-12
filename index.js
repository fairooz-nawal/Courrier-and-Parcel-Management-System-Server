const express = require('express');
const http = require("http"); // ✅ Import HTTP for Socket.IO
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const { Server } = require("socket.io");

dotenv.config();

const app = express(); // ✅ Define app BEFORE using it
const server = http.createServer(app); // ✅ Create server from app for Socket.IO

// Setup Socket.IO
const io = new Server(server, {
  cors: {
    origin: "*", // Allow frontend
    methods: ["GET", "POST"]
  }
});

app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const client = new MongoClient(process.env.MONGO_URI);
let db;

// Connect to MongoDB
async function connectDB() {
  try {
    await client.connect();
    db = client.db('courierDB');
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection error:', err);
  }
}
connectDB();

// JWT Middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Add user data to req
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
}

// 🛰️ Socket.IO events
io.on("connection", (socket) => {
  console.log("✅ A user connected: ", socket.id);

  // Listen for location updates from delivery agent
  socket.on("updateLocation", (data) => {
    console.log("📍 Parcel location updated:", data);

    // Broadcast to all clients (filter by parcelId if needed)
    io.emit(`parcelLocation-${data.parcelId}`, data);
  });

  socket.on("disconnect", () => {
    console.log("❌ A user disconnected: ", socket.id);
  });
});

// Routes
app.get('/', (req, res) => {
  res.send('🚀 Courier API is running');
});

// Register Route
// User Registration Route
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const usersCollection = db.collection("users");

    // Check if email exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into DB
    const newUser = {
      name,
      email,
      password: hashedPassword,
      role, // customer | agent | admin
      createdAt: new Date(),
    };

    const result = await usersCollection.insertOne(newUser);

    // Create JWT token
    const token = jwt.sign(
      { userId: result.insertedId, 
        role: role, 
        email: email },
      process.env.JWT_SECRET,
      { expiresIn: "356d" }
    );

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      token,
      user: {
        id: result.insertedId,
        name,
        email,
        role,
      },
    });
  } catch (error) {
    console.error("❌ Registration error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Login API
app.post("/api/login", async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const usersCollection = db.collection("users");

    // Check if user exists
    const user = await usersCollection.findOne({ email, role });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found or role mismatch" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid password" });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "365d" }
    );

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// backend/index.js
app.get("/api/verify-token", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ valid: false, message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ valid: true, user: decoded });
  } catch (err) {
    console.log("Token verification error:", err.message);
    res.status(401).json({ valid: false, message: "Invalid or expired token" });
  }
});

// POST /api/parcels
app.post("/api/parcels", authMiddleware, async (req, res) => {
  try {
    const { pickupAddress, deliveryAddress, parcelType, paymentMethod, pickupCoords, deliveryCoords, userId, userEmail } = req.body;

    if (!pickupAddress || !deliveryAddress || !parcelType || !paymentMethod || !pickupCoords || !deliveryCoords || !userId || !userEmail) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const parcelsCollection = db.collection("parcels");

    const newParcel = {
      pickupAddress,
      deliveryAddress,
      pickupCoords,
      deliveryCoords,
      parcelType,
      paymentMethod,
      userId,
      userEmail,
      status: "Pending", // initial status
      customerId: req.user.userId, // link parcel to logged-in customer
      createdAt: new Date(),
    };

    const result = await parcelsCollection.insertOne(newParcel);

    res.status(201).json({
      success: true,
      message: "Parcel created successfully",
      parcelId: result.insertedId,
    });
  } catch (err) {
    console.error("❌ Add Parcel Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// admin data
app.get("/api/admin/metrics", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ success: false, message: "Access denied" });
  }

  const totalBookings = await db.collection("parcels").countDocuments();
  const failedDeliveries = await db.collection("parcels").countDocuments({ status: "Failed" });
  const delivered = await db.collection("parcels").countDocuments({ status: "Delivered" });

  const codParcels = await db.collection("parcels").find({ paymentMethod: "COD" }).toArray();
  const totalCOD = codParcels.reduce((sum, parcel) => sum + (parcel.amount || 0), 0);

  const dailyStats = await db.collection("parcels").aggregate([
    {
      $group: {
        _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
        bookings: { $sum: 1 },
        failed: { $sum: { $cond: [{ $eq: ["$status", "Failed"] }, 1, 0] } },
      },
    },
    { $sort: { _id: 1 } },
  ]).toArray();

  res.json({
    totalBookings,
    failedDeliveries,
    delivered,
    totalCOD,
    dailyStats: dailyStats.map((day) => ({
      date: day._id,
      bookings: day.bookings,
      failed: day.failed,
    })),
  });
});

// GET /api/parcels (Admin only)
app.get("/api/parcels", authMiddleware, async (req, res) => {
  try {
    // Only allow admin
    if (req.user.role !== "admin") {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const parcels = await db.collection("parcels").find().toArray();
    res.json({ success: true, parcels });
  } catch (err) {
    console.error("❌ Get Parcels Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// GET /api/myparcels/:email (Fetch parcels for specific user)
app.get("/api/myparcels/:id", authMiddleware, async (req, res) => {
  try {
    const idFromParams = req.params.id; // Get email from URL
    const emailFromToken = req.user.userId;    // Get email from JWT payload

    // Check if user is trying to access their own parcels
    if (idFromParams !== emailFromToken) {
      return res
        .status(403)
        .json({ success: false, message: "Forbidden: Cannot access other users' parcels" });
    }

    // Query parcels created by this user
    const parcels = await db.collection("parcels").find({ userId: idFromParams}) // Match by user's email
      .sort({ createdAt: -1 })             // Most recent first
      .toArray();
    console.log(parcels);
    res.status(200).json({
      success: true,
      parcels,
    });
    
  } catch (err) {
    console.error("❌ Error fetching user parcels:", err);
    res.status(500).json({
      success: false,
      message: "Server error while fetching parcels",
    });
  }
});

// GET /api/parcels/:id
app.get("/api/parcels/:id", authMiddleware, async (req, res) => {
  try {
    const parcelId = req.params.id;

    const parcel = await db
      .collection("parcels")
      .findOne({ _id: new ObjectId(parcelId) });

    if (!parcel) {
      return res
        .status(404)
        .json({ success: false, message: "Parcel not found" });
    }

    res.json({ success: true, parcel });
  } catch (err) {
    console.error("❌ Get Parcel By ID Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// DELETE /api/parcels/:id - Delete a parcel (Customer or Admin)
app.delete("/api/parcels/:id", authMiddleware, async (req, res) => {
  try {
    const parcelId = req.params.id;

    // Check if ID is valid
    if (!ObjectId.isValid(parcelId)) {
      return res.status(400).json({ success: false, message: "Invalid parcel ID" });
    }

    const parcelsCollection = db.collection("parcels");

    // Find the parcel to check ownership or admin access
    const parcel = await parcelsCollection.findOne({ _id: new ObjectId(parcelId) });

    if (!parcel) {
      return res.status(404).json({ success: false, message: "Parcel not found" });
    }

    // Authorization check
    const isOwner = parcel.customerId === req.user.userId;
    const isAdmin = req.user.role === "admin";

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ success: false, message: "Unauthorized to delete this parcel" });
    }

    // Proceed with deletion
    await parcelsCollection.deleteOne({ _id: new ObjectId(parcelId) });

    res.status(200).json({ success: true, message: "Parcel deleted successfully" });
  } catch (err) {
    console.error("❌ Delete Parcel Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


// Protected Test Route
app.get('/api/profile', authMiddleware, async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) });
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/', (req, res) => {
  res.send('🚀 Courier API is running');
});

server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
