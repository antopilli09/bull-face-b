// converti-pin-a-hash.js
// Converte tutti i record con { pin } in { pin_hash } usando scrypt.
// Crea un backup e poi sovrascrive api/_data/dati.json.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FILE = path.join(process.cwd(), 'api', '_data', 'dati.json');
const BKP  = path.join(process.cwd(), 'api', '_data', `dati.backup.${Date.now()}.json`);

function mkHashFromPin(pin) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const outLen = 32;
  const key = crypto.scryptSync(String(pin), salt, outLen, { N, r, p });
  return `scrypt$N=${N},r=${r},p=${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

function convertRecord(rec) {
  if (!rec) return rec;
  if (Object.prototype.hasOwnProperty.call(rec, 'pin') && !rec.pin_hash) {
    const pinHash = mkHashFromPin(rec.pin);
    delete rec.pin;
    rec.pin_hash = pinHash;
  }
  return rec;
}

function convertDb(db) {
  if (Array.isArray(db)) {
    return db.map(convertRecord);
  }
  if (db && typeof db === 'object') {
    for (const k of Object.keys(db)) {
      db[k] = convertRecord(db[k]);
    }
    return db;
  }
  return db;
}

try {
  const raw = fs.readFileSync(FILE, 'utf-8');
  const json = JSON.parse(raw);

  fs.writeFileSync(BKP, JSON.stringify(json, null, 2));
  console.log('Backup creato:', BKP);

  const converted = convertDb(json);
  fs.writeFileSync(FILE, JSON.stringify(converted, null, 2));
  console.log('Conversione completata. File aggiornato:', FILE);

} catch (e) {
  console.error('Errore durante la conversione:', e);
  process.exit(1);
}
