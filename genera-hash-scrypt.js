// genera-hash-scrypt.js
const crypto = require('crypto');

const pin = process.argv[2];
if (!pin) { 
  console.log("Usa: node genera-hash-scrypt.js 1234");
  process.exit(1);
}

const salt = crypto.randomBytes(16);
crypto.scrypt(pin, salt, 32, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
  if (err) throw err;
  const res = `scrypt$N=16384,r=8,p=1$${salt.toString('base64')}$${derivedKey.toString('base64')}`;
  console.log(res);
});
