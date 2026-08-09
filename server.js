require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { cert, getApps, initializeApp } = require('firebase-admin/app');
const { getDatabase } = require('firebase-admin/database');

const app = express();

// CSP remains disabled because the current pages use inline CSS and scripts.
// Other Helmet protections are enabled without changing the existing UI.
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '100kb' }));

let db = null;

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
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    serviceAccount = {
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: normalizePrivateKey(process.env.FIREBASE_PRIVATE_KEY)
    };
  } else {
    serviceAccount = require('./firebase-key.json');
  }

  if (!getApps().length) {
    initializeApp({
      credential: cert(serviceAccount),
      databaseURL: process.env.FIREBASE_DATABASE_URL || 'https://vupc-official-web-default-rtdb.firebaseio.com'
    });
  }
  db = getDatabase();
  console.log('Firebase Admin Initialized');
} catch (error) {
  console.error('Firebase Admin initialization failed:', error.message);
}

function requireDb(req, res, next) {
  if (!db) {
    return res.status(503).json({ error: 'Database is temporarily unavailable.' });
  }
  return next();
}

function getAllowedAdmins() {
  return (process.env.ALLOWED_ADMINS || '')
    .split(',')
    .map(email => email.trim().toLowerCase())
    .filter(Boolean);
}

function getJwtSecret() {
  return process.env.JWT_SECRET || '';
}

function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').match(/^Bearer\s+(.+)$/i)?.[1];
  const secret = getJwtSecret();
  if (!token || !secret) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const payload = jwt.verify(token, secret);
    if (!getAllowedAdmins().includes(String(payload.email || '').toLowerCase())) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.admin = payload;
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { success: false, message: 'Too many login attempts. Please try again later.' }
});

const registrationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { success: false, message: 'Too many registration attempts. Please try again later.' }
});

class ValidationError extends Error {}

// This does not depend on Firebase, so it distinguishes a routing/runtime
// problem from a database configuration problem in production.
app.get('/api/health', (req, res) => {
  res.status(200).json({ ok: true, databaseReady: Boolean(db) });
});

function readText(value, maxLength, fieldName) {
  if (typeof value !== 'string') throw new ValidationError(`${fieldName} is required.`);
  const text = value.trim();
  if (!text || text.length > maxLength) throw new ValidationError(`${fieldName} is invalid.`);
  return text;
}

function validateRegistration(body) {
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const mobilePattern = /^01\d{9}$/;
  const studentIdPattern = /^\d{9}$/;
  const paymentMethods = new Set(['bKash', 'Nagad', 'Rocket']);
  const sourceMembers = body?.details?.membersFull;

  if (!body || typeof body !== 'object' || !Array.isArray(sourceMembers) || sourceMembers.length !== 3) {
    throw new ValidationError('Registration data is incomplete.');
  }

  const membersFull = sourceMembers.map((member, index) => {
    const name = readText(member?.name, 100, `Member ${index + 1} name`);
    const id = readText(member?.id, 20, `Member ${index + 1} student ID`);
    const semester = readText(member?.semester, 40, `Member ${index + 1} semester`);
    const mobile = readText(member?.mobile, 20, `Member ${index + 1} mobile`);
    const email = readText(member?.email, 160, `Member ${index + 1} email`).toLowerCase();
    const size = readText(member?.size, 10, `Member ${index + 1} t-shirt size`);
    if (!studentIdPattern.test(id) || !mobilePattern.test(mobile) || !emailPattern.test(email)) {
      throw new ValidationError(`Member ${index + 1} information is invalid.`);
    }
    return { name, id, semester, mobile, email, size };
  });

  const gateway = readText(body.gateway, 20, 'Payment method');
  const trx = readText(body.trx, 100, 'Transaction ID');
  const trxPhone = readText(body.trxPhone, 20, 'Transaction phone');
  const contactPerson = readText(body?.details?.contactPerson, 100, 'Contact person');
  if (!paymentMethods.has(gateway) || !mobilePattern.test(trxPhone)) {
    throw new ValidationError('Payment information is invalid.');
  }

  const contactMember = membersFull.find(member => member.name === contactPerson) || membersFull[0];
  return {
    name: readText(body.name, 100, 'Team name'),
    email: contactMember.email,
    contactEmail: contactMember.email,
    contactPhone: contactMember.mobile,
    members: membersFull.map(member => member.name).join(', '),
    gateway,
    trx,
    trxPhone,
    status: 'Active',
    createdAt: Date.now(),
    details: { membersFull, contactPerson }
  };
}

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  const email = (req.body?.email || '').trim().toLowerCase();
  const password = req.body?.password || '';
  const allowedAdmins = getAllowedAdmins();
  const storedHash = process.env.ADMIN_PASSWORD_HASH || '';
  const secret = getJwtSecret();

  if (!allowedAdmins.length || !storedHash || !secret) {
    console.error('Admin authentication configuration is incomplete.');
    return res.status(503).json({ success: false, message: 'Admin login is temporarily unavailable.' });
  }
  if (!allowedAdmins.includes(email) || !(await bcrypt.compare(password, storedHash))) {
    return res.status(401).json({ success: false, message: 'Invalid email or password.' });
  }

  const token = jwt.sign({ email }, secret, { expiresIn: '4h' });
  return res.set('Cache-Control', 'no-store').json({ success: true, token });
});

app.get('/api/admin/teams', requireDb, requireAdmin, async (req, res) => {
  try {
    const snapshot = await db.ref('teams').once('value');
    const data = snapshot.val();
    const teamsList = data ? Object.keys(data).map(id => ({ id, ...data[id] })) : [];
    return res.set('Cache-Control', 'no-store').json(teamsList);
  } catch (error) {
    console.error('Team fetch error:', error);
    return res.status(500).json({ error: 'Failed to fetch team data.' });
  }
});

app.patch('/api/admin/teams/:id', requireDb, requireAdmin, async (req, res) => {
  const teamId = req.params.id;
  const status = req.body?.status;
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(teamId) || !['Active', 'Pending', 'Verified'].includes(status)) {
    return res.status(400).json({ error: 'Invalid team update.' });
  }

  try {
    const ref = db.ref(`teams/${teamId}`);
    if (!(await ref.once('value')).exists()) return res.status(404).json({ error: 'Team not found.' });
    await ref.update({ status });
    return res.json({ success: true, status });
  } catch (error) {
    console.error('Team update error:', error);
    return res.status(500).json({ error: 'Failed to update team status.' });
  }
});

app.post('/api/register', registrationLimiter, requireDb, async (req, res) => {
  try {
    const teamData = validateRegistration(req.body);
    const newTeamRef = db.ref('teams').push();
    await newTeamRef.set(teamData);
    return res.status(201).json({ success: true, id: newTeamRef.key, message: 'Registration successful!' });
  } catch (error) {
    if (error instanceof ValidationError) return res.status(400).json({ error: error.message });
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Failed to save registration.' });
  }
});

const PORT = process.env.PORT || 5000;
if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
