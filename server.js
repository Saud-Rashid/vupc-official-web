require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const admin = require('firebase-admin');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// Firebase Admin Setup
const serviceAccount = require('./vupc-official-web-firebase-adminsdk-fbsvc-b9e7af3373.json');

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

const db = admin.firestore();

// 1. Admin Login Route
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;

  const allowedAdmins = (process.env.ALLOWED_ADMINS || '').split(',').map(e => e.trim().toLowerCase());
  const inputEmail = (email || '').trim().toLowerCase();

  // email check
  if (allowedAdmins.length > 0 && allowedAdmins[0] !== '' && !allowedAdmins.includes(inputEmail)) {
    return res.status(401).json({ error: 'Invalid Credentials' });
  }

  // pass check
  let isValid = false;
  if (password === 'admin1234') {
    isValid = true;
  }

  if (!isValid) {
    return res.status(401).json({ error: 'Invalid Credentials' });
  }

  // token generate
  const token = jwt.sign({ email: inputEmail }, process.env.JWT_SECRET || 'vupc_secret_key_2026', { expiresIn: '4h' });
  res.json({ success: true, token });
});

// 2. Fetch Teams Route (Real Data from Firestore)
app.get('/api/admin/teams', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const snapshot = await db.collection('teams').get();
    const teamsList = [];
    
    snapshot.forEach(doc => {
      teamsList.push({ id: doc.id, ...doc.data() });
    });

    res.json(teamsList);
  } catch (err) {
    console.error('Error fetching Firestore data:', err);
    res.status(500).json({ error: 'Failed to fetch teams data' });
  }
});

// 3. New Team Registration Route (Saves directly to Firebase)
app.post('/api/register', async (req, res) => {
  try {
    const teamData = req.body;
    teamData.createdAt = admin.firestore.FieldValue.serverTimestamp();
    teamData.verified = false; // default status

    const docRef = await db.collection('teams').add(teamData);
    res.json({ success: true, id: docRef.id, message: 'Registration successful!' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Failed to save registration' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));