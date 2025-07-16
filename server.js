// @ts-nocheck
require('dotenv').config();
const express          = require('express');
const bcrypt           = require('bcrypt');
const cookieParser     = require('cookie-parser');
const { MongoClient, ObjectId } = require('mongodb');
const { v4: uuidv4 }   = require('uuid');
const path             = require('path');
const axios            = require('axios');
const qs               = require('querystring');
const multer           = require('multer');
const { google }       = require('googleapis');
const { Readable }     = require('stream');      // ⬅️ NEW (for buffer→stream)

const app   = express();
const PORT  = process.env.PORT || 3000;
const COOKIE_NAME      = 'sid';
const SESSION_DURATION = 15 * 60 * 1000;        // 15 min

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

// ─── MongoDB ───────────────────────────────────────────────────────────────
const client = new MongoClient(process.env.MONGO_URI);
let usersCollection;

async function startServer() {
  try {
    await client.connect();
    usersCollection = client.db().collection('users');
    console.log('✅ Connected to MongoDB');

    app.listen(PORT, () =>
      console.log(`🚀  Server ready at http://localhost:${PORT}`)
    );
  } catch (err) {
    console.error('❌ Failed to start:', err);
    process.exit(1);
  }
}
startServer();

// ─── In‑memory sessions (demo) ─────────────────────────────────────────────
const SESSION_STORE = {};
function createSession(userId) {
  const sid = uuidv4();
  SESSION_STORE[sid] = { userId, expires: Date.now() + SESSION_DURATION };
  return sid;
}
function getSession(sid) {
  const s = SESSION_STORE[sid];
  if (!s || s.expires < Date.now()) { delete SESSION_STORE[sid]; return null; }
  return s;
}
async function authMiddleware(req, res, next) {
  const sid = req.cookies[COOKIE_NAME];
  const session = getSession(sid);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const user = await usersCollection.findOne(
    { _id: new ObjectId(session.userId) },
    { projection: { hashedPassword: 0 } }
  );
  if (!user) return res.status(401).json({ error: 'User not found' });

  req.user   = user;
  req.userId = session.userId;
  next();
}

// ─── Auth routes ──────────────────────────────────────────────────────────
// Signup
app.post('/auth/signup', async (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password)
    return res.status(400).json({ error: 'Missing fields' });

  if (await usersCollection.findOne({ email }))
    return res.status(400).json({ error: 'Email exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  const result = await usersCollection.insertOne({
    email, username, hashedPassword, plan: 'Free'
  });

  const sid = createSession(result.insertedId.toString());
  res
    .cookie(COOKIE_NAME, sid, {
      httpOnly: true, sameSite: 'lax', maxAge: SESSION_DURATION
    })
    .json({ message: 'Signup successful' });
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await usersCollection.findOne({ email });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const storedHash = user.hashedPassword || user.password;  // legacy fallback
  if (typeof storedHash !== 'string')
    return res.status(500).json({ error: 'Corrupt user record (no hash)' });

  const valid = await bcrypt.compare(password, storedHash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const sid = createSession(user._id.toString());
  res
    .cookie(COOKIE_NAME, sid, {
      httpOnly: true, sameSite: 'lax', maxAge: SESSION_DURATION
    })
    .json({ message: 'Login successful' });
});

// Current user
app.get('/auth/me', authMiddleware, (req, res) => {
  const { email, username, plan, youtube } = req.user;
  res.json({ email, username, plan, youtube: youtube || null });
});

// ─── YouTube OAuth ────────────────────────────────────────────────────────
app.get('/auth/youtube', authMiddleware, (req, res) => {
  const url = 'https://accounts.google.com/o/oauth2/v2/auth?' +
    qs.stringify({
      client_id:     process.env.GOOGLE_CLIENT_ID,
      redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
      response_type: 'code',
      scope: [
        'https://www.googleapis.com/auth/youtube.upload',
        'https://www.googleapis.com/auth/youtube.readonly',
        'https://www.googleapis.com/auth/userinfo.profile'
      ].join(' '),
      access_type: 'offline',
      prompt: 'consent',
    });
  res.redirect(url);
});

app.get('/auth/youtube/callback', async (req, res) => {
  const sid = req.cookies[COOKIE_NAME];
  const session = getSession(sid);
  if (!session) return res.status(401).send('Session invalid');

  const code = req.query.code;
  if (!code) return res.status(400).send('No code');

  try {
    const { data: tokens } = await axios.post(
      'https://oauth2.googleapis.com/token',
      qs.stringify({
        code,
        client_id:     process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
        grant_type:    'authorization_code',
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { data } = await axios.get(
      'https://www.googleapis.com/youtube/v3/channels',
      { headers: { Authorization: `Bearer ${tokens.access_token}` },
        params: { part: 'snippet', mine: true } }
    );

    const channel = data.items[0];
    await usersCollection.updateOne(
      { _id: new ObjectId(session.userId) },
      { $set: { youtube: {
        access_token: tokens.access_token,
        id: channel.id,
        channel: channel.snippet.title
      } } }
    );

    res.send(`<h2>YouTube linked: ${channel.snippet.title}</h2><a href="/">Back</a>`);
  } catch (err) {
    console.error(err);
    res.status(500).send('OAuth failed');
  }
});

// ─── Upload Shorts ────────────────────────────────────────────────────────
const upload = multer({ limits: { fileSize: 100 * 1024 * 1024 } });

app.post('/youtube/upload', authMiddleware, upload.single('video'), async (req, res) => {
    if (!req.user.youtube?.access_token)
      return res.status(401).json({ error: 'YouTube not linked' });
  
    const oauth2 = new google.auth.OAuth2();
    oauth2.setCredentials({ access_token: req.user.youtube.access_token });
    const youtube = google.youtube({ version: 'v3', auth: oauth2 });
  
    const { title, description } = req.body;
    const videoStream = Readable.from(req.file.buffer);
  
    try {
      const { data } = await youtube.videos.insert({
        part: 'snippet,status',
        requestBody: {
          snippet: { title, description: description || '', categoryId: '22' },
          status : { privacyStatus: 'public' },
        },
        media: { body: videoStream },
      });
  
      const videoUrl = `https://youtube.com/shorts/${data.id}`; // or /watch?v=
  
      res.json({
        message: 'Upload OK',
        videoId: data.id,
        videoUrl
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Upload failed' });
    }
  });
