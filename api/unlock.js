// api/unlock.js
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

// Rate limit semplice in RAM (si resetta a ogni cold start)
const attempts = new Map(); // key: ip|id  -> { count, firstAt }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 10 * 60 * 1000; // 10 minuti

function hit(key) {
  const now = Date.now();
  const rec = attempts.get(key);
  if (!rec) {
    attempts.set(key, { count: 1, firstAt: now });
    return { blocked: false };
  }
  // reset finestra
  if (now - rec.firstAt > WINDOW_MS) {
    attempts.set(key, { count: 1, firstAt: now });
    return { blocked: false };
  }
  rec.count += 1;
  attempts.set(key, rec);
  return { blocked: rec.count > MAX_ATTEMPTS };
}

module.exports = async (req, res) => {
  // CORS (se front-end e API sono sullo stesso dominio non serve,
  // ma non fa danni)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const { id, pin } = req.body || {};
    if (!id || !pin) {
      return res.status(400).json({ ok: false, error: 'Parametri mancanti' });
    }

    // rate limit per IP e per ID
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    if (hit(`${ip}|${id}`).blocked) {
      // non dire che è per troppi tentativi
      return res.status(401).json({ ok: false, error: 'Credenziali non valide' });
    }

    const jsonPath = path.join(process.cwd(), 'api', '_data', 'dati.json');
    const raw = fs.readFileSync(jsonPath, 'utf-8');
    const db = JSON.parse(raw);

    // dati.json è un oggetto indicizzato per id
    const rec = db[id];
    if (!rec || !rec.pin_hash) {
      // risposta neutra
      return res.status(401).json({ ok: false, error: 'Credenziali non valide' });
    }

    const okPin = await bcrypt.compare(String(pin), String(rec.pin_hash));
    if (!okPin) {
      return res.status(401).json({ ok: false, error: 'Credenziali non valide' });
    }

    // ✅ Successo: restituisci solo ciò che serve
    return res.status(200).json({
      ok: true,
      password: rec.password // oppure emetti un token temporaneo
    });

  } catch (e) {
    console.error('unlock error:', e);
    return res.status(500).json({ ok: false, error: 'Errore interno' });
  }
};
