require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ১. ফায়ারবেস অ্যাডমিন কানেকশন (ভার্সেল বা লোকাল দুটোতেই চলবে)
try {
  const serviceAccount = require('./firebase-key.json');
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://vupc-official-web-default-rtdb.firebaseio.com"
  });
  console.log("Firebase Admin Initialized!");
} catch (error) {
  console.log("Firebase Key not found locally, attempting default config...");
}

const db = admin.database();

// ২. ডাটাবেজ থেকে সব টিম পাওয়ার API
app.get('/api/data', async (req, res) => {
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

// ৩. ফর্ম থেকে নতুন টিম রেজিস্টার করে ফায়ারবেসে পাঠাবার API
app.post('/api/register', async (req, res) => {
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

// ৪. অ্যাডমিন লগইন রুট
app.post('/api/admin/login', (req, res) => {
  res.json({ success: true, token: "demo-token", message: "Login successful" });
});

// ৫. ফরগট পাসওয়ার্ড রুট
app.post('/api/admin/forgot-password', (req, res) => {
  const { email } = req.body;
  res.json({
    success: true,
    message: `Password reset instructions have been sent to ${email}`
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});