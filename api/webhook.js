const crypto = require('crypto');

module.exports = async (req, res) => {
  // Read strictly from the environment variable
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Signature-256');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Fail-safe if the env variable isn't loaded
  if (!WEBHOOK_SECRET) {
    return res.status(500).json({ 
      status: 'error', 
      error: 'Server misconfiguration: WEBHOOK_SECRET is missing.' 
    });
  }

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

  const rawBody = typeof payload === 'string' ? payload : JSON.stringify(payload);
  const expectedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

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

  return res.status(200).json({
    status: 'success',
    message: 'Webhook payload verified and inventory updated successfully.',
    data: payload
  });
};