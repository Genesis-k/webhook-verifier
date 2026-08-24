const crypto = require('crypto');

// Shared secret between warehouse and support service
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

module.exports = async (req, res) => {
  // Allow simple CORS for testing
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Signature-256');
  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed. Use POST.' });
  }

  const signature = req.headers['x-signature-256'];
  const payload = req.body;

  if (!signature) {
    return res.status(401).json({ 
      status: 'rejected', 
      error: 'Missing X-Signature-256 header' 
    });
  }

  // Calculate HMAC-SHA256 signature
  const rawBody = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  // Constant-time comparison to prevent timing attacks
  const signatureBuffer = Buffer.from(signature, 'hex');
  const expectedBuffer = Buffer.from(expectedSignature, 'hex');

  const isValid = signatureBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(signatureBuffer, expectedBuffer);

  if (!isValid) {
    return res.status(403).json({
      status: 'rejected',
      error: 'Invalid signature verification failed',
      received: signature
    });
  }

  // Process valid payload (e.g., Stock Update)
  return res.status(200).json({
    status: 'success',
    message: 'Webhook payload verified and inventory updated successfully.',
    data: payload,
    timestamp: new Date().toISOString()
  });
};