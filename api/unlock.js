// /api/unlock.js
const fs = require('fs');
const path = require('path');

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { id, pin } = req.body || {};
    if (!id || !pin) return res.status(400).json({ error: 'Missing id or pin' });

    // Legge dati.json dal deploy (non pubblico via browser)
    const jsonPath = path.join(process.cwd(), 'dati.json');
    const data = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));

    const rec = data[id];
    if (!rec) return res.status(404).json({ error: 'ID not found' });

    if (String(pin) !== String(rec.pin)) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    return res.status(200).json({ ok: true, secret: rec.password });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
};
