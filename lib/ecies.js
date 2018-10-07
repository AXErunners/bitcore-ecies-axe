'use strict';

var bitcore = require('@axerunners/axecore-lib');

var PublicKey = bitcore.PublicKey;
var Hash = bitcore.crypto.Hash;
var Random = bitcore.crypto.Random;
var $ = bitcore.util.preconditions;
const base58 = bitcore.encoding.Base58;


var AESCBC = require('./aescbc');

// http://en.wikipedia.org/wiki/Integrated_Encryption_Scheme
var ECIES = function ECIES(opts) {
  if (!(this instanceof ECIES)) {
    return new ECIES();
  }
  this.opts = opts || {};
};

ECIES.prototype.privateKey = function (privateKey) {
  $.checkArgument(privateKey, 'no private key provided');

  this._privateKey = privateKey || null;

  return this;
};

ECIES.prototype.publicKey = function (publicKey) {
  $.checkArgument(publicKey, 'no public key provided');

  this._publicKey = publicKey || null;

  return this;
};

ECIES.prototype.blsSecretKey = function (secretKey) {
  $.checkArgument(secretKey, 'no secret key provided');

  this._blsSecretKey = secretKey || null;
  return this;
};

ECIES.prototype.blsPublicKey = function (publicKey) {
  $.checkArgument(publicKey, 'no public key provided');

  this._blsPublicKey = publicKey || null;
  return this;
};

ECIES.prototype.cache = new Map();

ECIES.prototype.getSharedSecret = function (bls, skString, pkString, key = 'sharedSec') {
  if (!this.cache.has(key)) {
    this.cache.set(key, dhKeyExchange(bls, skString, pkString));
  }
  return this.cache.get(key);
}

// Key derivation function for subkey kE
ECIES.prototype.getKDF_kE = function (bls, skString, pkString, key = 'kE') {
  if (!this.cache.has(key)) {
    this.cache.set(key, this.getSharedSecret(bls, skString, pkString).slice(0, 32));
  }
  return this.cache.get(key);
}

// Key derivation function for subkey kM
ECIES.prototype.getKDF_kM = function (bls, skString, pkString, key = 'kM') {
  if (!this.cache.has(key)) {
    this.cache.set(key, this.getSharedSecret(bls, skString, pkString).slice(64, 128));
  }
  return this.cache.get(key);
}

var cachedProperty = function (name, getter) {
  var cachedName = '_' + name;
  Object.defineProperty(ECIES.prototype, name, {
    configurable: false,
    enumerable: true,
    get: function () {
      var value = this[cachedName];
      if (!value) {
        value = this[cachedName] = getter.apply(this);
      }
      return value;
    }
  });
};

cachedProperty('Rbuf', function () {
  return this._privateKey.publicKey.toDER(true);
});

cachedProperty('kEkM', function () {
  var r = this._privateKey.bn;
  var KB = this._publicKey.point;
  var P = KB.mul(r);
  var S = P.getX();
  var Sbuf = S.toBuffer({size: 32});
  return Hash.sha512(Sbuf);
});

cachedProperty('kE', function () {
  return this.kEkM.slice(0, 32);
});

cachedProperty('kM', function () {
  return this.kEkM.slice(32, 64);
});

const getBlsPublickeyBase58 = function (bls, skString) {
  const sk = bls.secretKeyImport(Buffer.from(skString, 'hex'));
  const pk = bls.publicKey();
  bls.getPublicKey(pk, sk);
  return new Buffer(base58.encode(Buffer.from(bls.publicKeyExport(pk))));
};

const dhKeyExchange = function (bls, skString, pkString) {
  const sk = bls.secretKeyImport(Buffer.from(skString, 'hex'));
  const sharedSec = bls.publicKey();
  const pub = bls.publicKeyImport(Buffer.from(pkString, 'hex'));
  // Diffie-Helllman Key Exchange
  bls.dhKeyExchange(sharedSec, sk, pub);
  const arrSharedSec = bls.publicKeyExport(sharedSec);
  // free the pointers
  bls.free(sk);
  bls.free(sharedSec);
  bls.free(pub);
  return Buffer.from(arrSharedSec);
};

// Encrypts the message (String or Buffer).
// Optional `ivbuf` contains 16-byte Buffer to be used in AES-CBC.
// By default, `ivbuf` is computed deterministically from message and private key using HMAC-SHA256.
// Deterministic IV enables end-to-end test vectors for alternative implementations.
// Note that identical messages have identical ciphertexts. If your protocol does not include some
// kind of a sequence identifier inside the message *and* it is important to not allow attacker to learn
// that message is repeated, then you should use custom IV.
// For random IV, pass `Random.getRandomBuffer(16)` for the second argument.
ECIES.prototype.encrypt = function (message, ivbuf) {
  if (!Buffer.isBuffer(message)) message = new Buffer(message);
  if (ivbuf === undefined) {
    ivbuf = Hash.sha256hmac(message, this._privateKey.toBuffer()).slice(0, 16);
  }
  var c = AESCBC.encryptCipherkey(message, this.kE, ivbuf);
  var d = Hash.sha256hmac(c, this.kM);
  if (this.opts.shortTag) d = d.slice(0, 4);
  if (this.opts.noKey) {
    var encbuf = Buffer.concat([c, d]);
  } else {
    var encbuf = Buffer.concat([this.Rbuf, c, d]);
  }
  return encbuf;
};

// Encrypts the message (String or Buffer) for BLS keys.
// Requires bls arg to do the Diffie-Hellman exchange.
// Optional `ivbuf` contains 16-byte Buffer to be used in AES-CBC.
// By default, `ivbuf` is computed deterministically from message and private key using HMAC-SHA256.
// Deterministic IV enables end-to-end test vectors for alternative implementations.
// Note that identical messages have identical ciphertexts. If your protocol does not include some
// kind of a sequence identifier inside the message *and* it is important to not allow attacker to learn
// that message is repeated, then you should use custom IV.
// For random IV, pass `Random.getRandomBuffer(16)` for the second argument.
ECIES.prototype.encryptBLS = function (bls, message, ivbuf) {
  if (!bls || !this._blsSecretKey || !this._blsPublicKey) {
    throw new Error('bls object must be passed and keys must be set');
  }
  if (!Buffer.isBuffer(message)) message = new Buffer(message);
  if (ivbuf === undefined) {
    ivbuf = Hash.sha256hmac(message, Buffer.from(this._blsSecretKey, 'hex')).slice(0, 16);
  }
  const c = AESCBC.encryptCipherkey(message, this.getKDF_kE(bls, this._blsSecretKey, this._blsPublicKey), ivbuf);
  let d = Hash.sha256hmac(c, this.getKDF_kM(bls, this._blsSecretKey, this._blsPublicKey));
  if (this.opts.shortTag) d = d.slice(0, 4);
  let encbuf;
  if (this.opts.noKey) {
    encbuf = Buffer.concat([c, d]);
  } else {
    encbuf = Buffer.concat([getBlsPublickeyBase58(bls, this._blsSecretKey), c, d]);
  }
  return encbuf;
};

ECIES.prototype.decrypt = function (encbuf) {
  $.checkArgument(encbuf);
  var offset = 0;
  var tagLength = 32;
  if (this.opts.shortTag) {
    tagLength = 4;
  }
  if (!this.opts.noKey) {
    offset = 33;
    this._publicKey = PublicKey.fromDER(encbuf.slice(0, 33));
  }

  var c = encbuf.slice(offset, encbuf.length - tagLength);
  var d = encbuf.slice(encbuf.length - tagLength, encbuf.length);

  var d2 = Hash.sha256hmac(c, this.kM);
  if (this.opts.shortTag) d2 = d2.slice(0, 4);

  var equal = true;
  for (var i = 0; i < d.length; i++) {
    equal &= (d[i] === d2[i]);
  }
  if (!equal) {
    throw new Error('Invalid checksum');
  }

  return AESCBC.decryptCipherkey(c, this.kE);
};

ECIES.prototype.decryptBLS = function (bls, encbuf) {
  if (!bls || !this._blsSecretKey) {
    throw new Error('bls object must be passed and keys must be set');
  }
  $.checkArgument(encbuf);
  var offset = 0;
  var tagLength = 32;
  if (this.opts.shortTag) {
    tagLength = 4;
  }
  if(!this.opts.noKey) {
    offset = 88;
    this._blsPublicKey = base58.decode(encbuf.slice(0, offset).toString());
  }

  var c = encbuf.slice(offset, encbuf.length - tagLength);
  var d = encbuf.slice(encbuf.length - tagLength, encbuf.length);

  var d2 = Hash.sha256hmac(c, this.getKDF_kM(bls, this._blsSecretKey, this._blsPublicKey));
  if (this.opts.shortTag) d2 = d2.slice(0, 4);

  var equal = true;
  for (var i = 0; i < d.length; i++) {
    equal &= (d[i] === d2[i]);
  }
  if (!equal) {
    throw new Error('Invalid checksum');
  }

  return AESCBC.decryptCipherkey(c, this.getKDF_kE(bls, this._blsSecretKey, this._blsPublicKey));
};
module.exports = ECIES;
