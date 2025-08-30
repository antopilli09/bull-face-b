// api/validate-token.js
const crypto = require('crypto');
const { derivePassword } = require('./unlock');

const MASTER_SECRET = process.env.MASTER_SECRET || 'DEV-CHANGE-ME';

// verifica token "payload.sig"
function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', MASTER_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return null;

  try {
    const obj = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!obj || !obj.id || !obj.exp) return null;
    if (Date.now() > obj.exp) return null; // scaduto
    return obj; // { id, exp }
  } catch {
    return null;
  }
}

module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  const { token } = req.query || {};
  const data = verifyToken(token);
  if (!data) {
    return res.status(401).json({ ok: false, error: 'Token non valido o scaduto' });
  }

  const password = derivePassword(data.id);
  return res.status(200).json({ ok: true, password });
};
