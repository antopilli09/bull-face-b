// api/unlock.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function verifyScrypt(pin, stored) {
  const [alg, params, saltB64, hashB64] = String(stored).split('$');
  if (alg !== 'scrypt') return false;

  const cfg = Object.fromEntries(params.split(',').map(x => x.split('=')));
  const N = parseInt(cfg.N, 10), r = parseInt(cfg.r, 10), p = parseInt(cfg.p, 10);
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');

  const derived = crypto.scryptSync(String(pin), salt, expected.length, { N, r, p });
  return crypto.timingSafeEqual(derived, expected);
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok:false, error:'Method not allowed' });
  }

  try {
    const { id, pin } = req.body || {};
    if (!id || !pin) return res.status(400).json({ ok:false, error:'Parametri mancanti' });

    const jsonPath = path.join(process.cwd(), 'api', '_data', 'dati.json');
    const db = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));

    const rec = db[id];
    if (!rec || !rec.pin_hash) {
      return res.status(401).json({ ok:false, error:'Credenziali non valide' });
    }

    const okPin = verifyScrypt(pin, rec.pin_hash);
    if (!okPin) {
      return res.status(401).json({ ok:false, error:'Credenziali non valide' });
    }

    return res.status(200).json({ ok:true, password: rec.password });
  } catch (e) {
    console.error('unlock error:', e);
    return res.status(500).json({ ok:false, error:'Errore interno' });
  }
};
