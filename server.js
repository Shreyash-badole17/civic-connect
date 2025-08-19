require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const uri = process.env.MONGODB_URI;
let dbReady = false;

if (uri && /^mongodb(\+srv)?:\/\//.test(uri)) {
  mongoose
    .connect(uri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => {
      dbReady = true;
      console.log('MongoDB connected');
    })
    .catch((err) => console.error('MongoDB connection error:', err.message));
} else {
  console.warn(
    'Skipping MongoDB connection: set MONGODB_URI to a valid MongoDB connection string.'
  );
}

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

const User = mongoose.model('User', userSchema);

app.post('/api/register', async (req, res) => {
  if (!dbReady) return res.status(503).json({ error: 'Database not connected' });
  try {
    const { email, password } = req.body;
    const user = new User({ email, password });
    await user.save();
    res.status(201).json({ message: 'User registered' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  if (!dbReady) return res.status(503).json({ error: 'Database not connected' });
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    res.json({ message: 'Login successful' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
