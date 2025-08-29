// api/validate-token.js
const { tokens, derivePassword } = require('./unlock');

module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ ok:false, error:'Method not allowed' });
  }

  const { token } = req.query;
  const rec = token && tokens[token];
  if (!rec) return res.status(401).json({ ok:false, error:'Token non valido' });

  if (Date.now() > rec.exp) {
    delete tokens[token];
    return res.status(401).json({ ok:false, error:'Token scaduto' });
  }

  // Password FISSA derivata da ID + MASTER_SECRET
  const password = derivePassword(rec.id);
  return res.status(200).json({ ok:true, password });
};
