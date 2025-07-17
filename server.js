require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { MongoClient, ObjectId } = require('mongodb'); // ObjectId might be needed
const axios = require('axios');

// --- Our new imports ---
const authRoutes = require('./routes/authRoutes');
// We will create analysisRoutes later
// const analysisRoutes = require('./routes/analysisRoutes');
const cookieParser = require('cookie-parser'); // For reading JWT from cookie

const app = express();

// --- CORS Configuration ---
const clientURL = process.env.CLIENT_URL;
console.log(`[CORS Setup] Allowed Client URL from env: ${clientURL}. NODE_ENV: ${process.env.NODE_ENV}`);

const corsOptions = {
  origin: (origin, callback) => {
    console.log(`[CORS Check] Request from origin: ${origin}. Allowed clientURL: ${clientURL}`);
    // If the request's origin matches your CLIENT_URL, allow it.
    // This is the most important check for browser requests with credentials.
    if (origin === clientURL) {
      callback(null, true);
    } 
    // For development, allow tools like Postman that might not send an origin.
    // For Render's health checks that might not have an origin header.
    else if (!origin && process.env.NODE_ENV !== 'production') { 
      console.log(`[CORS Check] No origin, non-production. Allowing.`);
      callback(null, true);
    }
    // Explicitly allow Render's typical health check behavior (no origin) even in production
    // This is a guess; Render's health check behavior might vary.
    // A more robust solution for health checks is to have a dedicated health check endpoint
    // that doesn't go through such strict CORS.
    else if (!origin && process.env.NODE_ENV === 'production') {
        console.log(`[CORS Check] No origin, production env (possibly health check). Allowing.`);
        callback(null, true); // Temporarily allow this to see if it unblocks browser
    }
    else {
      console.error(`[CORS Error] Origin '${origin}' not allowed.`);
      callback(new Error(`Origin '${origin}' not allowed by CORS policy.`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
};

app.use(cors(corsOptions));

// --- Body Parsers ---
app.use(express.json({ limit: '10kb' })); // For JSON payloads (login, register)
app.use(express.urlencoded({ extended: true, limit: '10kb' })); // For form data (not multipart)
app.use(cookieParser()); // For parsing cookies

const upload = multer(); // Keep using multer for file uploads

const client = new MongoClient(process.env.MONGODB_URI);
// let db; // We will pass db via app.locals

client.connect()
  .then(() => {
    // db = client.db('resumeAnalyzer'); // Store db instance in app.locals
    app.locals.db = client.db('resumeAnalyzer');
    console.log('✅ Connected to MongoDB Atlas');

    // Create indexes for users collection if they don't exist
    const usersCollection = app.locals.db.collection('users');
    usersCollection.createIndex({ email: 1 }, { unique: true })
      .then(() => console.log('Email index created for users collection.'))
      .catch(err => console.error('Error creating email index:', err));
    usersCollection.createIndex({ emailVerificationToken: 1 })
      .then(() => console.log('Email verification token index created.'))
      .catch(err => console.error('Error creating verification token index:', err));

  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Health check
app.get('/', (req, res) => {
  res.send('Smart Resume Analyzer backend is running!');
});

// --- Mount Routers ---
app.use('/api/auth', authRoutes);
// app.use('/api/analyses', analysisRoutes); // We will add this later

// Analyze & tailor route (will be moved/modified later)
app.post('/api/analyze', upload.fields([{ name: 'resume' }, { name: 'job' }]), async (req, res) => {
  const db = req.app.locals.db; // Access db from app.locals
  if (!db) return res.status(503).json({ error: 'Database not connected yet.' });

  try {
    const extractText = file => file.buffer.toString('utf-8');
    const resumeText = extractText(req.files['resume'][0]);
    const jobText = extractText(req.files['job'][0]);

    // 1. Keyword extraction via DeepSeek-R1 on OpenRouter
    const orRes = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: 'deepseek/deepseek-r1:free', // Ensure this model is still available and free
        messages: [
          { role: 'system', content: 'Extract important keywords from the given job description. Respond with a comma-separated list.' },
          { role: 'user', content: jobText }
        ]
      },
      {
        headers: {
          'Authorization': `Bearer ${process.env.OPENROUTER_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );

    const raw = orRes.data.choices[0].message.content.trim();
    const keywords = raw.split(',').map(k => k.trim()).filter(k => k.length);

    const stringSimilarity = require('string-similarity');
    const levenshtein = require('fast-levenshtein');

    const COSINE_THRESHOLD = 0.75;
    const LEVENSHTEIN_MAX_DISTANCE = 2;

    const resumeLower = resumeText.toLowerCase();
    const matched = [];
    const missing = [];

    for (const k of keywords) {
        const keywordLower = k.toLowerCase();

        if (resumeLower.includes(keywordLower)) {
            matched.push(k);
            continue;
        }

        const words = resumeLower.split(/\s+/);
        const hasCosineMatch = words.some(word => 
            stringSimilarity.compareTwoStrings(word, keywordLower) >= COSINE_THRESHOLD
        );
        if (hasCosineMatch) {
            matched.push(k);
            continue;
        }

        const hasLevenshteinMatch = words.some(word => 
            levenshtein.get(word, keywordLower) <= LEVENSHTEIN_MAX_DISTANCE
        );
        if (hasLevenshteinMatch) {
            matched.push(k);
            continue;
        }
        missing.push(k);
    }

    const score = keywords.length ? matched.length / keywords.length : 0;

    const analysisData = {
      // userId: null, // We will add this later when user is authenticated
      resumeText, jobText, keywords, matched, missing, score,
      date: new Date()
    };

    // For now, we'll keep saving analyses anonymously.
    // We'll update this when implementing protected routes.
    await db.collection('analyses').insertOne(analysisData);

    res.json({ score, matched, missing, keywords });
  } catch (err) {
    console.error('Error during analysis:', err.response?.data || err.message);
    res.status(500).json({ error: 'Analysis failed', details: err.message });
  }
});

const PORT = process.env.PORT || 6000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));