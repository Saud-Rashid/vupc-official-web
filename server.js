require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const { cert, getApps, initializeApp } = require('firebase-admin/app');
const { getDatabase } = require('firebase-admin/database');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ---------------------------------------------------------------
// Firebase Admin Setup — env variable থেকে নেওয়া হচ্ছে (Vercel-এ
// raw JSON ফাইল ডিপ্লয় করার দরকার নেই), guarded try/catch দিয়ে
// যাতে init fail করলেও পুরো সার্ভার crash না করে।
// ---------------------------------------------------------------
let db = null;

// A private key copied from a JSON/config file can accidentally retain its
// wrapping quote and trailing comma in a .env value. Firebase expects the PEM
// text only, so normalize that common format before creating the credential.
function normalizePrivateKey(value) {
  let key = String(value || '').trim();

  if (key.startsWith('"') || key.startsWith("'")) {
    const quote = key[0];
    key = key.slice(1).replace(new RegExp(`${quote}?\\s*,?\\s*$`), '');
  }

  return key.replace(/\\n/g, '\n');
}

try {
  let serviceAccount;

  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // Option A: পুরো service account JSON একটাই env variable-এ
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    // Option B: আলাদা আলাদা env variable (তোমার বর্তমান Vercel সেটআপ)।
    // PRIVATE_KEY-তে literal "\n" থাকে, আসল newline-এ কনভার্ট করা লাগবে।
    serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: normalizePrivateKey(process.env.FIREBASE_PRIVATE_KEY)
    };
  } else {
    // Local development fallback: ফাইল থেকে নেওয়া
    serviceAccount = require('./firebase-key.json');
  }

  if (!getApps().length) {
    initializeApp({
      credential: cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL || "https://vupc-official-web-default-rtdb.firebaseio.com"
    });
  }

  db = getDatabase();
  console.log("Firebase Admin Initialized!");
} catch (error) {
  console.error("Firebase Admin init failed:", error.message);
}

function requireDb(req, res, next) {
  if (!db) {
    return res.status(503).json({
      error: "Database not initialized. Check Firebase env variables / server logs."
    });
  }
  next();
}

// ---------------------------------------------------------------
// স্টার্টআপ ডায়াগনস্টিকস — Vercel Function Logs-এ গিয়ে দেখা যাবে
// কোন env variable সেট আছে/নেই (আসল ভ্যালু কখনো লগ হয় না)
// ---------------------------------------------------------------
console.log("=== ENV CHECK ===");
console.log("ALLOWED_ADMINS set:", !!process.env.ALLOWED_ADMINS, "| value:", process.env.ALLOWED_ADMINS || "(missing)");
console.log("ADMIN_PASSWORD_HASH set:", !!process.env.ADMIN_PASSWORD_HASH, "| length:", (process.env.ADMIN_PASSWORD_HASH || '').length);
console.log("JWT_SECRET set:", !!process.env.JWT_SECRET);
console.log("FIREBASE_SERVICE_ACCOUNT set:", !!process.env.FIREBASE_SERVICE_ACCOUNT);
console.log("FIREBASE_PROJECT_ID/CLIENT_EMAIL/PRIVATE_KEY set:",
  !!process.env.FIREBASE_PROJECT_ID, !!process.env.FIREBASE_CLIENT_EMAIL, !!process.env.FIREBASE_PRIVATE_KEY);
console.log("==================");

// 1. Admin Login Route
app.post('/api/admin/login', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = req.body.password || '';

  const allowedAdmins = (process.env.ALLOWED_ADMINS || '')
    .split(',')
    .map(e => e.trim().toLowerCase())
    .filter(Boolean);

  // email check
  if (allowedAdmins.length > 0 && !allowedAdmins.includes(email)) {
    console.log("Login blocked - email not in ALLOWED_ADMINS:", email);
    return res.status(401).json({ success: false, message: 'অনুমোদিত ইমেইল নয়!' });
  }

  // pass check — এখন সত্যিকারের bcrypt hash-এর বিপরীতে যাচাই হচ্ছে,
  // আগের মতো hardcoded 'admin1234' স্ট্রিং না
  const storedHash = process.env.ADMIN_PASSWORD_HASH || '';
  if (!storedHash) {
    console.error("ADMIN_PASSWORD_HASH env variable is missing/empty!");
    return res.status(500).json({ success: false, message: 'সার্ভার কনফিগারেশন ত্রুটি: পাসওয়ার্ড হ্যাশ সেট করা নেই।' });
  }

  const isValid = await bcrypt.compare(password, storedHash);

  if (!isValid) {
    console.log("Login blocked - wrong password for:", email);
    return res.status(401).json({ success: false, message: 'ভুল পাসওয়ার্ড!' });
  }

  // token generate
  const token = jwt.sign({ email }, process.env.JWT_SECRET || 'vupc_secret_key_2026', { expiresIn: '4h' });
  res.json({ success: true, token });
});

// 2. Fetch Teams Route (Realtime Database থেকে ডাটা আনা) — token verify করে
app.get('/api/admin/teams', requireDb, async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');

  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    jwt.verify(token, process.env.JWT_SECRET || 'vupc_secret_key_2026');
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  try {
    const ref = db.ref('teams');
    const snapshot = await ref.once('value');
    const data = snapshot.val();

    const teamsList = [];
    if (data) {
      Object.keys(data).forEach(key => {
        teamsList.push({ id: key, ...data[key] });
      });
    }

    res.json(teamsList);
  } catch (err) {
    console.error('Error fetching Realtime Database data:', err);
    res.status(500).json({ error: 'Failed to fetch teams data' });
  }
});

// 3. New Team Registration Route (Realtime Database-এ সেভ করা)
app.post('/api/register', requireDb, async (req, res) => {
  try {
    const teamData = req.body;
    teamData.createdAt = Date.now();
    teamData.verified = false;

    const ref = db.ref('teams');
    const newTeamRef = ref.push();
    await newTeamRef.set(teamData);

    res.json({ success: true, id: newTeamRef.key, message: 'Registration successful!' });
  } catch (err) {
    console.error('Registration error:', err); 
    res.status(500).json({ error: 'Failed to save registration' });
  }
});

const PORT = process.env.PORT || 5000;

// Vercel-এ এই ফাইলটা module হিসেবে import হয় (app.listen চলে না)।
// লোকালে "node server.js" দিয়ে সরাসরি রান করলে তখনই app.listen চলবে।
if (require.main === module) {
  app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
}

module.exports = app;
