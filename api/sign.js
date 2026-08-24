const crypto = require('crypto');

module.exports = async (req, res) => {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    return res.status(500).json({ error: 'WEBHOOK_SECRET is not configured on the server.' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { payload, tamper } = req.body;
  const rawBody = typeof payload === 'string' ? payload : JSON.stringify(payload);

  let signature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');

  // If testing failure case, corrupt the signature
  if (tamper) {
    signature = 'invalid_sig_' + signature.substring(12);
  }

  return res.status(200).json({ signature, payload: rawBody });
};