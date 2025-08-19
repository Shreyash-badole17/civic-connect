import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const app = express();

// --- security & parsing ---
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));
app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 200 }));

// --- db ---
await mongoose.connect(process.env.MONGO_URI);
console.log('Mongo connected');

// --- user model ---
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// --- helpers ---
function sign(user) {
  return jwt.sign({ uid: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
}
function authGuard(req, res, next) {
  const token = req.cookies.token || (req.headers.authorization||'').replace('Bearer ','');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// --- routes ---
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Invalid input' });
  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ error: 'Email already in use' });
  const passwordHash = await bcrypt.hash(password, 12);
  const user = await User.create({ email, passwordHash });
  const token = sign(user);
  res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV==='production', sameSite: 'lax', maxAge: 86400000 });
  res.json({ ok: true, email: user.email });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  const token = sign(user);
  res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV==='production', sameSite: 'lax', maxAge: 86400000 });
  res.json({ ok: true, email: user.email });
});

app.get('/api/auth/me', authGuard, (req, res) => {
  res.json({ ok:true, user: { email: req.user.email }});
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token'); res.json({ ok: true });
});

app.listen(process.env.PORT, () => console.log('API on :' + process.env.PORT));
