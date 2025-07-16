const express = require('express');
const bcrypt = require('bcrypt');
const qs = require('querystring');
const axios = require('axios');
const { ObjectId } = require('mongodb');
const authMiddleware = require('../middleware/auth');
const { createSession, SESSION_DURATION, getSession } = require('../utils/sessionStore');

const router = express.Router();
const COOKIE_NAME = 'sid';

// ──────────────────────────────────────────────────────────────
// Signup
router.post('/signup', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password)
    return res.status(400).json({ error: 'Missing fields' });

  const users = req.app.locals.usersCollection;

  if (await users.findOne({ email }))
    return res.status(400).json({ error: 'Email already exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  const result = await users.insertOne({
    email,
    username,
    hashedPassword,
    plan: 'Free'
  });

  const sid = createSession(result.insertedId.toString());
  res
    .cookie(COOKIE_NAME, sid, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_DURATION,
    })
    .json({ message: 'Signup successful' });
});

// ──────────────────────────────────────────────────────────────
// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const users = req.app.locals.usersCollection;

  const user = await users.findOne({ email });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const storedHash = user.hashedPassword || user.password; // legacy fallback
  if (typeof storedHash !== 'string')
    return res.status(500).json({ error: 'Corrupt user record (no hash)' });

  const valid = await bcrypt.compare(password, storedHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const sid = createSession(user._id.toString());
  res
    .cookie(COOKIE_NAME, sid, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_DURATION,
    })
    .json({ message: 'Login successful' });
});

// ──────────────────────────────────────────────────────────────
// Get current user
router.get('/me', authMiddleware, (req, res) => {
  const { email, username, plan, youtube } = req.user;
  res.json({ email, username, plan, youtube: youtube || null });
});

// ──────────────────────────────────────────────────────────────
// YouTube OAuth: Redirect user to Google
router.get('/youtube', authMiddleware, (req, res) => {
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' +
    qs.stringify({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: process.env.GOOGLE_REDIRECT_URI,
      response_type: 'code',
      scope: [
        'https://www.googleapis.com/auth/youtube.upload',
        'https://www.googleapis.com/auth/youtube.readonly',
        'https://www.googleapis.com/auth/userinfo.profile'
      ].join(' '),
      access_type: 'offline', // Needed for refresh_token
      prompt: 'consent'        // Always ask for consent (ensures refresh_token)
    });

  res.redirect(url);
});

// ──────────────────────────────────────────────────────────────
// YouTube OAuth callback
router.get('/youtube/callback', async (req, res) => {
  const sid = req.cookies[COOKIE_NAME];
  const session = getSession(sid);
  if (!session) return res.status(401).send('Session invalid');

  const code = req.query.code;
  if (!code) return res.status(400).send('No code');

  try {
    // Exchange code for tokens
    const { data: tokens } = await axios.post(
      'https://oauth2.googleapis.com/token',
      qs.stringify({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // Fetch YouTube channel
    const { data } = await axios.get(
      'https://www.googleapis.com/youtube/v3/channels',
      {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
        params: { part: 'snippet', mine: true }
      }
    );

    const channel = data.items[0];
    const users = req.app.locals.usersCollection;

    // Store tokens + channel info
    await users.updateOne(
      { _id: new ObjectId(session.userId) },
      {
        $set: {
          youtube: {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token, // may be undefined if reused
            expires_in: tokens.expires_in,
            fetched_at: Date.now(),
            id: channel.id,
            channel: channel.snippet.title
          }
        }
      }
    );

    res.send(`<h2>✅ YouTube linked: ${channel.snippet.title}</h2><a href="/">Back</a>`);
  } catch (err) {
    console.error('❌ YouTube OAuth error:', err.response?.data || err.message);
    res.status(500).send('OAuth failed');
  }
});

module.exports = router;
