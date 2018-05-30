import iota from "./services/iota";
import Encryption from "./utils/encryption";

import { FILE } from "./config";
import forge from "node-forge";

export const generate = (genesisHash, size, opts = {}) => {
  let offsets = 1; // Meta chunk

  if (opts.includeTreasureOffsets) {
    // Includes 1 treasure per sector.
    const numTreasureChunks = Math.ceil(size / (FILE.CHUNKS_PER_SECTOR - 1));
    offsets += numTreasureChunks;
  }

  const keys = Array.from(Array(size + offsets), (_, i) => i);

  const [dataMap] = keys.reduce(
    ([dataM, hash], i) => {
      const [obfuscatedHash, nextHash] = Encryption.hashChain(hash);
      dataM[i] = iota.toAddress(iota.utils.toTrytes(obfuscatedHash));
      return [dataM, nextHash];
    },
    [{}, forge.util.hexToBytes(genesisHash)]
  );
  return dataMap;
};

const rawGenerate = (genesisHash, size) => {
  const keys = _.range(1, size);

  const [dataMap, _hash] = _.reduce(
    keys,
    ([dataM, hash], i) => {
      const [_obfuscatedHash, nextHash] = Encryption.hashChain(hash);
      dataM[i] = nextHash;

      return [dataM, nextHash];
    },
    [{}, forge.util.hexToBytes(genesisHash)]
  );

  dataMap[0] = genesisHash;

  return dataMap;
};

const {
  genesisHash,
  decryptChunk,
  encryptChunk,
  getPrimordialHash,
  getSalt,
  obfuscate,
  parseEightCharsOfFilename,
  sideChain,
  decryptTreasure} = Encryption;

export default {
  generate,
  genesisHash,
  rawGenerate,
  decryptChunk,
  encryptChunk,
  getPrimordialHash,
  getSalt,
  obfuscate,
  parseEightCharsOfFilename,
  sideChain,
  decryptTreasure
};
