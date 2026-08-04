require('dotenv').config();
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors({ origin: '*' }));
app.use(express.json());

// ১. ডাটা পাঠনোর জন্য API Endpoint (ওয়েবসাইটে আসল ডাটা দেখাবে)
app.get('/api/data', (req, res) => {
  res.json([
    { id: 1, title: "VUPC Event 1", status: "Active", description: "Official Contest" },
    { id: 2, title: "VUPC Event 2", status: "Upcoming", description: "Registration Soon" }
  ]);
});

// ২. এডমিন লগইন রুট (লগইন বাটন কাজ করানোর জন্য)
app.post('/api/admin/login', async (req, res) => {
  const { email, password } = req.body;
  res.json({ success: true, token: "demo-token", message: "Login successful" });
});

// ৩. সার্ভার পোর্ট লিসেনার
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
app.post('/api/admin/forgot-password', (req, res) => {
  const { email } = req.body;
  res.json({ 
    success: true, 
    message: `Password reset instructions have been sent to ${email}` 
  });
});