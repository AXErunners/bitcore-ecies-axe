const bls = require('bls-lib');
const ECIES = require('../');
const bitcore = require('@axerunners/axecore-lib');
const PrivateKey = bitcore.PrivateKey;

bls.onModuleInit(() => {
  // need to wait for wasm module to load

  const aliceKey = new PrivateKey('XFKfS6jQ1ic2xonndSD2Rtvwb2GRE5XJG7q2ScBnRhSJQU5zXGD9');
  const bobKey = new PrivateKey('XHYLVEzU6S4SJHAw3qoBM4PJqNHyLLSrYM2edrcEAuzBUS55LjeA');
  const blsAliceSecretKey = 'c9f8757408490beab646153e9a2d9f77d539b8efde4c850e6c447ffc7de09617';
  const blsBobSecretKey = 'ca7efeb61b1949bb27128be551a715b89afb6f30775feb05d141e3826351751d';
  const blsAlicePublicKey = 'b01f107d6c1378579e1ea8ec3711c9237460db077bc8ba65c158a78f9b43f22470c275133b1bb0fa3fa5dc23d2d15972924a99ae0d3a05f5c5a510fe3fde0e03';
  const blsBobPublicKey = 'e91c74ffe36c81fdf1a08146fc9a890701adf051fcc779630525ae1babe62c106ea1b36d3c8c9327f4cc2db6beff44a73df7a29c16982b8e5b3d4016b0a93d0c';

  // plain old ecdsa
  const alice = ECIES()
    .privateKey(aliceKey)
    .publicKey(bobKey.publicKey);

  const bob = ECIES()
    .privateKey(bobKey)
    .publicKey(aliceKey.publicKey);

  console.log(bob._publicKey);
  const message = 'attack at dawn';

  console.log(`encrypting message "${message}"`);
  console.log('with ecdsa');

  const ciphertext = alice.encrypt(message);
  console.log('ecdsa cipher:', ciphertext.toString('hex'));

  let decrypted = bob.decrypt(ciphertext).toString();
  console.log('decrypted:', decrypted);

  // shiny new bls
  const blsAlice = ECIES()
    .blsSecretKey(blsAliceSecretKey)
    .blsPublicKey(blsBobPublicKey);

  const blsBob = ECIES()
    .blsSecretKey(blsBobSecretKey)
    .blsPublicKey(blsAlicePublicKey);

  console.log('with bls');

  bls.init();

  const blsCiphertext = blsAlice.encryptBLS(bls, message);
  console.log('bls cipher:', blsCiphertext.toString('hex'));

  const blsDecrypted = blsBob.decryptBLS(bls, blsCiphertext).toString();
  console.log('bls decrypted:', blsDecrypted);

  blsAlice.opts.noKey = true;
  blsBob.opts.noKey = true;
  const encrypted = blsAlice.encryptBLS(bls, message);
  decrypted = blsBob.decryptBLS(bls, encrypted).toString();

  console.log('bls no key cipher:', encrypted.toString('hex'));
  console.log('bls no key decrypted:', decrypted);
});