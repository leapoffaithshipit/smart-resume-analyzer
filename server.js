require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const axios = require('axios');
const cookieParser = require('cookie-parser'); // For reading JWT from cookie

const app = express();


app.use(cors());

// --- Body Parsers ---
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

const upload = multer();

// --- Health check ---
app.get('/', (req, res) => {
  res.send('Smart Resume Analyzer backend is running!');
});

// --- Analyze Route (Mongo Removed) ---
app.post('/api/analyze', upload.fields([{ name: 'resume' }, { name: 'job' }]), async (req, res) => {
  try {
    const extractText = file => file.buffer.toString('utf-8');
    const resumeText = extractText(req.files['resume'][0]);
    const jobText = extractText(req.files['job'][0]);

    const orRes = await axios.post(
      'https://openrouter.ai/api/v1/chat/completions',
      {
        model: 'deepseek/deepseek-r1:free',
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

    res.json({ score, matched, missing, keywords });
  } catch (err) {
    console.error('Error during analysis:', err.response?.data || err.message);
    res.status(500).json({ error: 'Analysis failed', details: err.message });
  }
});

// --- Start Server ---
const PORT = process.env.PORT || 10000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
