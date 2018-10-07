'use strict';

var ECIES = require('../');
const bls = require('bls-lib');
var should = require('chai').should();
var bitcore = require('@axerunners/axecore-lib');
var PrivateKey = bitcore.PrivateKey;


var aliceKey = new PrivateKey('XFKfS6jQ1ic2xonndSD2Rtvwb2GRE5XJG7q2ScBnRhSJQU5zXGD9');
var bobKey = new PrivateKey('XHYLVEzU6S4SJHAw3qoBM4PJqNHyLLSrYM2edrcEAuzBUS55LjeA');

describe('ECIES', function () {

  it('constructor', function () {
    (typeof ECIES).should.equal('function');
  });

  it('constructs an instance', function () {
    var ecies = new ECIES();
    (ecies instanceof ECIES).should.equal(true);
  });

  it('doesnt require the "new" keyword', function () {
    var ecies = ECIES();
    (ecies instanceof ECIES).should.equal(true);
  });

  it('errors', function () {
    should.exist(bitcore.errors.ECIES);
  });

});

describe('ECDSA', function () {

  it('ECDSA: privateKey fails with no argument', function () {
    var ecies = ECIES();
    var fail = function () {
      ecies.privateKey();
    };
    fail.should.throw('no private key provided');
  });

  it('ECDSA: publicKey fails with no argument', function () {
    var ecies = ECIES();
    var fail = function () {
      ecies.publicKey();
    };
    fail.should.throw('no public key provided');
  });

  it('ECDSA: chainable function', function () {
    var ecies = ECIES()
      .privateKey(aliceKey)
      .publicKey(bobKey.publicKey);

    (ecies instanceof ECIES).should.equal(true);

  });

  var alice = ECIES()
    .privateKey(aliceKey)
    .publicKey(bobKey.publicKey);

  var bob = ECIES()
    .privateKey(bobKey)
    .publicKey(aliceKey.publicKey);

  var message = 'attack at dawn';
  var encrypted = '0259e3da1349903aaaf3ff0d389e8086d669a9e7ae464be5b53131b590f872d96ceccc4c78c4b0b16e45f3982e4535acda1b63edfc4ebe81fd02539c4f7d720f4f206476303796e4b0d0ae247d117355fa661710dbce76d9b97ccf731040af60b1';
  var encBuf = new Buffer(encrypted, 'hex');

  it('ECDSA: correctly encrypts a message', function () {
    var ciphertext = alice.encrypt(message);
    Buffer.isBuffer(ciphertext).should.equal(true);
    ciphertext.toString('hex').should.equal(encrypted)
  });

  it('ECDSA: correctly decrypts a message', function () {
    var decrypted = bob
      .decrypt(encBuf)
      .toString();
    decrypted.should.equal(message);
  });

  it('ECDSA: retrieves senders publickey from the encypted buffer', function () {
    var bob2 = ECIES().privateKey(bobKey);
    var decrypted = bob2.decrypt(encBuf).toString();
    bob2._publicKey.toDER().should.deep.equal(aliceKey.publicKey.toDER());
    decrypted.should.equal(message);
  });

  it('ECDSA: roundtrips', function () {
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('ECDSA: roundtrips (no public key)', function () {
    alice.opts.noKey = true;
    bob.opts.noKey = true;
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('ECDSA: roundtrips (short tag)', function () {
    alice.opts.shortTag = true;
    bob.opts.shortTag = true;
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('ECDSA: roundtrips (no public key & short tag)', function () {
    alice.opts.noKey = true;
    alice.opts.shortTag = true;
    bob.opts.noKey = true;
    bob.opts.shortTag = true;
    var secret = 'some secret message!!!';
    var encrypted = alice.encrypt(secret);
    var decrypted = bob
      .decrypt(encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('ECDSA: correctly fails if trying to decrypt a bad message', function () {
    var encrypted = bitcore.util.buffer.copy(encBuf);
    encrypted[encrypted.length - 1] = 2;
    (function () {
      return bob.decrypt(encrypted);
    }).should.throw('Invalid checksum');
  });

});

const blsAliceSecretKey = 'c9f8757408490beab646153e9a2d9f77d539b8efde4c850e6c447ffc7de09617';
const blsBobSecretKey = 'ca7efeb61b1949bb27128be551a715b89afb6f30775feb05d141e3826351751d';
const blsAlicePublicKey = 'b01f107d6c1378579e1ea8ec3711c9237460db077bc8ba65c158a78f9b43f22470c275133b1bb0fa3fa5dc23d2d15972924a99ae0d3a05f5c5a510fe3fde0e03';
const blsBobPublicKey = 'e91c74ffe36c81fdf1a08146fc9a890701adf051fcc779630525ae1babe62c106ea1b36d3c8c9327f4cc2db6beff44a73df7a29c16982b8e5b3d4016b0a93d0c';

describe('BLS', function () {

  beforeEach(() => {
    bls.onModuleInit(() => {
      bls.init();
    });
  });

  it('BLS: blsSecretKey fails with no argument', function () {
    const ecies = ECIES();
    const fail = function () {
      ecies.blsSecretKey();
    };
    fail.should.throw('no secret key provided');
  });

  it('BLS: blsPublicKey fails with no argument', function () {
    var ecies = ECIES();
    var fail = function () {
      ecies.blsPublicKey();
    };
    fail.should.throw('no public key provided');
  });

  it('BLS: chainable function', function () {
    const ecies = ECIES()
      .blsSecretKey(blsAliceSecretKey)
      .blsPublicKey(blsBobPublicKey);

    (ecies instanceof ECIES).should.equal(true);

  });

  const blsAlice = ECIES()
    .blsSecretKey(blsAliceSecretKey)
    .blsPublicKey(blsBobPublicKey);

  const blsBob = ECIES()
    .blsSecretKey(blsBobSecretKey)
    .blsPublicKey(blsAlicePublicKey);

  const message = 'attack at dawn';
  const encrypted = '345845524279753253424b704b4e326b7a58344a624a4b6b533261427334447469397555433735763338634a395238334457584a4a4b566d6b5347484364656b64474e4e334d7465756f4a57594c75567033694b7039486bf1f2de7190928473c9d0949e7e03bb2863f3fe306551524c500af6d2b203101cc36d76f872109d45d53d0bb85ff31c0f8ac1336f1d049ab9756548e11c699e31';
  const encBuf = new Buffer(encrypted, 'hex');

  it('BLS: correctly encrypts a message', function () {
    const ciphertext = blsAlice.encryptBLS(bls, message);
    Buffer.isBuffer(ciphertext).should.equal(true);
    ciphertext.toString('hex').should.equal(encrypted)
  });

  it('BLS: correctly decrypts a message', function () {
    var decrypted = blsBob
      .decryptBLS(bls, encBuf)
      .toString();
    decrypted.should.equal(message);
  });

  it('BLS: retrieves senders publickey from the encypted buffer', function() {
    var blsBob2 = ECIES().blsSecretKey(blsBobSecretKey);
    var decrypted = blsBob2.decryptBLS(bls, encBuf).toString();
    decrypted.should.equal(message);
  });

  it('BLS: roundtrips', function () {
    var secret = 'some secret message!!!';
    var encrypted = blsAlice.encryptBLS(bls, secret);
    var decrypted = blsBob
      .decryptBLS(bls, encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('BLS: roundtrips (no public key)', function () {
    blsAlice.opts.noKey = true;
    blsBob.opts.noKey = true;
    var secret = 'some secret message!!!';
    var encrypted = blsAlice.encryptBLS(bls, secret);
    var decrypted = blsBob
      .decryptBLS(bls, encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('BLS: roundtrips (short tag)', function () {
    blsAlice.opts.shortTag = true;
    blsBob.opts.shortTag = true;
    var secret = 'some secret message!!!';
    var encrypted = blsAlice.encryptBLS(bls, secret);
    var decrypted = blsBob
      .decryptBLS(bls, encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('BLS: roundtrips (no public key & short tag)', function () {
    blsAlice.opts.noKey = true;
    blsAlice.opts.shortTag = true;
    blsBob.opts.noKey = true;
    blsBob.opts.shortTag = true;
    var secret = 'some secret message!!!';
    var encrypted = blsAlice.encryptBLS(bls, secret);
    var decrypted = blsBob
      .decryptBLS(bls, encrypted)
      .toString();
    decrypted.should.equal(secret);
  });

  it('BLS: correctly fails if trying to decrypt a bad message', function () {
    var encrypted = bitcore.util.buffer.copy(encBuf);
    encrypted[encrypted.length - 1] = 2;
    (function () {
      return blsBob.decryptBLS(bls, encrypted);
    }).should.throw('Invalid checksum');
  });

});
