require('dotenv').config();
const express = require('express');
const path = require('path');
const webhookHandler = require('./api/webhook');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Mount the serverless function handler to Express
app.post('/api/webhook', (req, res) => webhookHandler(req, res));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Local test server running at http://localhost:${PORT}`);
});