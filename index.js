const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const client = new MongoClient(process.env.MONGO_URI);
let db;

// Connect to MongoDB
async function connectDB() {
  try {
    await client.connect();
    db = client.db('courierDB'); // Your database name
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

// Register Route
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const userExists = await db.collection('users').findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      name,
      email,
      password: hashedPassword,
      role: role || 'Customer', // Default role
      createdAt: new Date()
    };

    await db.collection('users').insertOne(newUser);
    res.status(201).json({ message: '✅ User registered successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await db.collection('users').findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
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

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
