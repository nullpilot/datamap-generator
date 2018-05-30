import { sha3_256 } from "js-sha3";
import forge from "node-forge";
// can't import iota from services/iota because the iota.lib.js tries to run
// curl.init() during the unit tests
import iotaUtils from "iota.lib.js/lib/utils/asciiToTrytes";
import _ from "lodash";

// an eth private seed key is 64 characters, the treasure prefix is 20 characters,
// and our tags are 32 characters
const PAYLOAD_LENGTH = 64;
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const TREASURE_TRYTE_LENGTH = PAYLOAD_LENGTH * 2 + IV_LENGTH * 2 + TAG_LENGTH * 2;

const parseEightCharsOfFilename = fileName => {
  fileName = fileName + getSalt(8);
  fileName = fileName.substr(0, 8);

  return fileName;
};

// `length` should be a multiple of 8
export function getSalt(length) {
  const bytes = forge.random.getBytesSync(length);
  const byteArr = forge.util.binary.raw.decode(bytes);
  const salt = forge.util.binary.base58.encode(byteArr);
  return salt.substr(0, length);
}

export function getPrimordialHash() {
  const bytes = forge.random.getBytesSync(16);
  return forge.md.sha256
    .create()
    .update(bytes)
    .digest()
    .toHex();
}

const obfuscate = hash => {
  const byteStr = forge.util.hexToBytes(hash);
  return forge.md.sha384
    .create()
    .update(byteStr)
    .digest()
    .toHex();
} // Forge.util.binary.raw.decode(bytes)

const sideChain = address => sha3_256(address);

const decryptTreasure = (sideChainHash, signatureMessageFragment) => {
  const key = sideChainHash
  const secret = iotaUtils.fromTrytes(
    signatureMessageFragment.substring(0, TREASURE_TRYTE_LENGTH)
  );

  const treasure = decryptChunk(key, secret);

  return treasure.length === PAYLOAD_LENGTH ? treasure : false;
};

// Genesis hash is not yet obfuscated.
const genesisHash = handle => {
  const [_obfuscatedHash, genHash] = hashChain(handle);

  return genHash;
};

// Expects byteString as input
// Returns [obfuscatedHash, nextHash] as byteString
export function hashChain(byteStr) {
  const obfuscatedHash = forge.md.sha384
    .create()
    .update(byteStr)
    .digest()
    .bytes();
  const nextHash = forge.md.sha256
    .create()
    .update(byteStr)
    .digest()
    .bytes();

  return [obfuscatedHash, nextHash];
}

const encryptChunk = (key, idx, secret) => {
  key.read = 0;
  const iv = getNonce(key, idx);
  const cipher = forge.cipher.createCipher("AES-GCM", key);

  cipher.start({
    iv: iv,
    tagLength: TAG_LENGTH * 8,
    additionalData: "binary-encoded string"
  });

  cipher.update(forge.util.createBuffer(secret));
  cipher.finish();

  return cipher.output.bytes() + cipher.mode.tag.bytes() + iv;
};

const decryptChunk = (key, secret) => {
  key.read = 0;

  // Require a payload of at least one byte to attempt decryption
  if (secret.length <= IV_LENGTH + TAG_LENGTH) {
    return "";
  }

  const iv = secret.substr(-IV_LENGTH);
  const tag = secret.substr(-TAG_LENGTH - IV_LENGTH, TAG_LENGTH);
  const decipher = forge.cipher.createDecipher("AES-GCM", key);

  decipher.start({
    iv: iv,
    tag: tag,
    tagLength: TAG_LENGTH * 8,
    additionalData: "binary-encoded string"
  });

  decipher.update(
    forge.util.createBuffer(
      secret.substring(0, secret.length - TAG_LENGTH - IV_LENGTH)
    )
  );

  // Most likely a treasure chunk, skip
  if (!decipher.finish()) {
    return "";
  }

  return decipher.output.bytes();
};


export default {
  hashChain,
  genesisHash,
  decryptChunk,
  encryptChunk,
  getPrimordialHash,
  getSalt,
  obfuscate,
  parseEightCharsOfFilename,
  sideChain,
  decryptTreasure
};
