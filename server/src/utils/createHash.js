const crypto = require('crypto');

const hashToken = (token => {
  crypto.createHash(process.env.CRYPTO_HASH_ALGORITHM).update(token).digest(process.env.CRYPTO_HASH_ENCODING);
});

module.exports = { hashToken };