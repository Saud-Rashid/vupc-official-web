require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ১. ফায়ারবেস অ্যাডমিন কানেকশন (ভার্সেল বা লোকাল দুটোতেই চলবে)
let db = null;

try {
  let serviceAccount;
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // Vercel/deployed environment: env variable থেকে নেওয়া
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else {
    // Local development: ফাইল থেকে নেওয়া
    serviceAccount = require('./firebase-key.json');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://vupc-official-web-default-rtdb.firebaseio.com"
  });

  db = admin.database();
  console.log("Firebase Admin Initialized!");
} catch (error) {
  // এখানে ক্র্যাশ না করে শুধু লগ করা হচ্ছে, যাতে পুরো সার্ভার নামিয়ে না দেয়
  console.error("Firebase Admin init failed:", error.message);
}

// db initialize না হলে (Firebase env var missing/ভুল থাকলে) সংশ্লিষ্ট রুটগুলো
// পরিষ্কার 503 error দেবে, পুরো function crash করবে না
function requireDb(req, res, next) {
  if (!db) {
    return res.status(503).json({
      error: "Database not initialized. Check FIREBASE_SERVICE_ACCOUNT env variable / server logs."
    });
  }
  next();
}

// ২. ডাটাবেজ থেকে সব টিম পাওয়ার API
app.get('/api/data', requireDb, async (req, res) => {
  try {
    const ref = db.ref('teams');
    const snapshot = await ref.once('value');
    const data = snapshot.val();

    if (!data) return res.json([]);

    const teamList = Object.keys(data).map(key => ({
      id: key,
      ...data[key]
    }));

    res.json(teamList);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ৩. ফর্ম থেকে নতুন টিম রেজিস্টার করে ফায়ারবেসে পাঠাবার API
app.post('/api/register', requireDb, async (req, res) => {
  try {
    const teamData = req.body;
    const ref = db.ref('teams');
    const newTeamRef = ref.push();

    await newTeamRef.set({
      name: teamData.name || teamData.teamName || 'Unknown Team',
      email: teamData.email || 'N/A',
      members: teamData.members || '3 Members',
      gateway: teamData.gateway || 'bKash',
      trx: teamData.trx || 'N/A',
      status: 'Active',
      createdAt: new Date().toISOString()
    });

    res.json({ success: true, message: "Registered successfully in Firebase!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ৪. অ্যাডমিন লগইন রুট (Secure) — ডাটাবেজের দরকার নেই, তাই requireDb লাগেনি
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  const allowedAdmins = (process.env.ALLOWED_ADMINS || '').split(',');

  // ১. ইমেইল অনুমোদিত কি না চেক
  if (!allowedAdmins.includes(email)) {
    return res.status(401).json({ success: false, message: "অনুমোদিত ইমেইল নয়!" });
  }

  try {
    // ২. .env এর HASH এর সাথে পাসওয়ার্ড ম্যাচ করা
    const isMatch = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH || '');

    if (!isMatch) {
      return res.status(401).json({ success: false, message: "ভুল পাসওয়ার্ড!" });
    }

    // ৩. JWT Token জেনারেট করা
    const token = jwt.sign({ email }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '2h' });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, message: "সার্ভার এরর!" });
  }
});

// ৫. ফরগট পাসওয়ার্ড রুট
app.post('/api/admin/forgot-password', (req, res) => {
  const { email } = req.body;
  res.json({
    success: true,
    message: `Password reset instructions have been sent to ${email}`
  });
});

const PORT = process.env.PORT || 5000;

// Vercel-এ এই ফাইলটা module হিসেবে import হয় (app.listen চলে না, serverless
// runtime নিজেই request হ্যান্ডল করে)। লোকালে সরাসরি "node server.js" দিয়ে
// রান করলে require.main === module সত্যি হবে, তখনই শুধু app.listen চলবে।
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;