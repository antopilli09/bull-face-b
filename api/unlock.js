// api/unlock.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function verifyScrypt(pin, stored) {
  // formato: scrypt$N=...,r=...,p=...$<saltB64>$<hashB64>
  const [alg, params, saltB64, hashB64] = String(stored).split('$');
  if (alg !== 'scrypt') return false;

  const cfg = Object.fromEntries(params.split(',').map(x => x.split('=')));
  const N = parseInt(cfg.N, 10), r = parseInt(cfg.r, 10), p = parseInt(cfg.p, 10);
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');

  const derived = crypto.scryptSync(String(pin), salt, expected.length, { N, r, p });
  return crypto.timingSafeEqual(derived, expected);
}

// Deriva una password FISSA per l'ID usando un segreto master
function derivePassword(id) {
  const master = process.env.MASTER_SECRET;
  if (!master) throw new Error('MASTER_SECRET non definita');

  // HMAC-SHA256(master, id) → codifica base32 (20 char)
  const hmac = crypto.createHmac('sha256', master).update(String(id)).digest();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '', out = '';
  for (const b of hmac) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length && out.length < 20; i += 5) {
    out += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  }
  return out; // sempre uguale per stesso id + master
}

// Archivio token temporanei (RAM; si svuota ai cold start)
const tokens = {};

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok:false, error:'Method not allowed' });
  }

  try {
    const { id, pin } = req.body || {};
    if (!id || !pin) return res.status(400).json({ ok:false, error:'Parametri mancanti' });

    // Legge il DB (solo PIN hashati)
    const jsonPath = path.join(process.cwd(), 'api', '_data', 'dati.json');
    const db = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));

    const rec = db[id];
    if (!rec || !rec.pin_hash) {
      return res.status(401).json({ ok:false, error:'Credenziali non valide' });
    }

    if (!verifyScrypt(pin, rec.pin_hash)) {
      return res.status(401).json({ ok:false, error:'Credenziali non valide' });
    }

    // ✅ Genera token monouso (valido 60s)
    const token = crypto.randomBytes(16).toString('hex');
    tokens[token] = { id, exp: Date.now() + 60_000 };

    return res.status(200).json({ ok:true, token });
  } catch (e) {
    console.error('unlock error:', e);
    return res.status(500).json({ ok:false, error:'Errore interno' });
  }
};

// Esporta per l'altra API
module.exports.tokens = tokens;
module.exports.derivePassword = derivePassword;
