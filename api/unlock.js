// api/unlock.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const MASTER_SECRET = process.env.MASTER_SECRET || 'DEV-CHANGE-ME';

// derivazione password deterministica da ID + MASTER_SECRET
function derivePassword(id) {
  return crypto
    .createHash('sha256')
    .update(`${id}:${MASTER_SECRET}`)
    .digest('base64')
    .slice(0, 16);
}

// token HMAC "payload.sig", payload = base64url({ id, exp })
function signToken(payloadObj) {
  const payload = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto.createHmac('sha256', MASTER_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const { id, pin } = req.body || {};
    if (!id || !pin) return res.status(400).json({ ok: false, error: 'Missing id or pin' });

    // leggi solo dalla cartella privata
    const jsonPath = path.join(__dirname, '_data', 'dati.json');
    const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

    const rec = data[id];
    if (!rec) return res.status(404).json({ ok: false, error: 'ID not found' });

    if (String(pin) !== String(rec.pin)) {
      return res.status(401).json({ ok: false, error: 'Invalid PIN' });
    }

    // crea token che scade tra 2 minuti
    const exp = Date.now() + 2 * 60 * 1000;
    const token = signToken({ id, exp });

    return res.status(200).json({ ok: true, token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
};

// esporto per riuso da validate-token.js
module.exports.derivePassword = derivePassword;
