require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');

const connectToMongo = require('./config/db');
const authRoutes = require('./routes/auth');
const youtubeRoutes = require('./routes/youtube');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));
app.use('/auth', authRoutes);
app.use('/youtube', youtubeRoutes);

connectToMongo(app, PORT);