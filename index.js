const bip39 = require('bip39')
const createHmac = require("create-hmac");
const { instantiate } = require("js-nacl/lib/nacl_factory");
const sha512 = require('js-sha512');
const base32 = require('hi-base32');
const algo = require('algosdk')
var ED25519_CURVE = 'ed25519 seed';
var HARDENED_OFFSET = 0x80000000;
var naclInstance = void 0;

instantiate(function (nacl) {
  console.log('call this one');
  return naclInstance = nacl;
});
var replaceDerive = function replaceDerive(val) {
  return val.replace("'", '');
};

const CKDPriv = function CKDPriv(_ref, index) {
  var key = _ref.key,
    chainCode = _ref.chainCode;

  var indexBuffer = Buffer.allocUnsafe(4);
  indexBuffer.writeUInt32BE(index, 0);
  var data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);
  var I = createHmac('sha512', chainCode).update(data).digest();
  var IL = I.slice(0, 32);
  var IR = I.slice(32);
  return {
    key: IL,
    chainCode: IR
  };
};

const getMasterKeyFromSeed = function getMasterKeyFromSeed(seed) {
  var hmac = createHmac('sha512', ED25519_CURVE);
  var I = hmac.update(Buffer.from(seed, 'hex')).digest();
  var IL = I.slice(0, 32);
  var IR = I.slice(32);
  return {
    key: IL,
    chainCode: IR
  };
};


const derivePath = function derivePath(path, seed) {
  var _getMasterKeyFromSeed = getMasterKeyFromSeed(seed),
    key = _getMasterKeyFromSeed.key,
    chainCode = _getMasterKeyFromSeed.chainCode;
  console.log({ path })

  var segments = path.split('/').slice(1).map(replaceDerive).map(function (el) {
    return parseInt(el, 10);
  });
  console.log({ segments })

  return segments.reduce(function (parentKeys, segment) {
    return CKDPriv(parentKeys, segment + HARDENED_OFFSET);
  }, { key: key, chainCode: chainCode });
};

function concatArrays(a, b) {
  var c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

var getPublicKey = function getPublicKey(privateKey) {
  var _naclInstance$crypto_ = naclInstance.crypto_sign_seed_keypair(privateKey),
    signPk = _naclInstance$crypto_.signPk;

  return Buffer.from(signPk);
};
function encode(address) {
  //compute checksum
  var checksum = sha512.sha512_256.array(address).slice(28, 32);
  var addr = base32.encode(concatArrays(address, checksum));

  return addr.toString().slice(0, 58); // removing the extra '===='
}


const accountHelper = async (mnemonics) => {
  try {
    const seed = await bip39.mnemonicToSeed(mnemonics);
    var algoPath = "m/44'/283'/0'/0'/0'";
    var childKeys = derivePath(algoPath, seed);
    var pubKey = getPublicKey(childKeys.key);
    var encodedPubKey = encode(pubKey);
    const acc = algo.masterDerivationKeyToMnemonic(childKeys.key)
    return {
      address: encodedPubKey,
      privKey: childKeys.key.toString('hex'),
      publicKey: pubKey.toString('hex'),
      acc
    };
  } catch (error) {
    console.log(error);
  }
}

accountHelper('maple move steak prefer blossom rare magnet home struggle prefer believe eagle leaf tomorrow tortoise').then(console.log)