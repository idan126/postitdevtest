const express = require('express');
const multer = require('multer');
const { google } = require('googleapis');
const { Readable } = require('stream');
const { ObjectId } = require('mongodb');
const authMiddleware = require('../middleware/auth');

const router = express.Router();
const upload = multer({ limits: { fileSize: 100 * 1024 * 1024 } });

router.post('/upload', authMiddleware, upload.single('video'), async (req, res) => {
  const youtubeData = req.user.youtube;
  if (!youtubeData?.access_token)
    return res.status(401).json({ error: 'YouTube not linked' });

  const oauth2 = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );

  try {
    const tokenAge = Date.now() - (youtubeData.fetched_at || 0);

    // Refresh if older than 58 mins
    if (tokenAge > 3500 * 1000 && youtubeData.refresh_token) {
      const { credentials } = await oauth2.refreshToken(youtubeData.refresh_token);

      // Save new token to DB
      await req.app.locals.usersCollection.updateOne(
        { _id: new ObjectId(req.userId) },
        {
          $set: {
            'youtube.access_token': credentials.access_token,
            'youtube.fetched_at': Date.now()
          }
        }
      );

      oauth2.setCredentials({ access_token: credentials.access_token });
    } else {
      oauth2.setCredentials({ access_token: youtubeData.access_token });
    }

    const youtube = google.youtube({ version: 'v3', auth: oauth2 });
    const { title, description } = req.body;
    const videoStream = Readable.from(req.file.buffer);

    const { data } = await youtube.videos.insert({
      part: 'snippet,status',
      requestBody: {
        snippet: { title, description: description || '', categoryId: '22' },
        status: { privacyStatus: 'public' },
      },
      media: { body: videoStream },
    });

    const videoUrl = `https://youtube.com/shorts/${data.id}`;
    res.json({ message: 'Upload OK', videoId: data.id, videoUrl });
  } catch (err) {
    console.error('❌ YouTube Upload Error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Upload failed', details: err.message });
  }
});

module.exports = router;
