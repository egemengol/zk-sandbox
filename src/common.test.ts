import { Bytes, Hash } from 'o1js';
import { sha3_256 } from '@noble/hashes/sha3';
import {
  Bytes32,
  SignerElliptic,
  findSubarrayIndex,
  hashToScalar,
} from './common';

describe('common', () => {
  let signer: SignerElliptic;

  beforeAll(async () => {
    signer = new SignerElliptic();
  });

  it('hash verify', async () => {
    const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const hash = sha3_256(payload);
    const hashO1: Bytes32 = Hash.SHA3_256.hash(Bytes.from(payload));
    for (let i = 0; i < 32; i += 1) {
      expect(hash[i]).toEqual(hashO1.bytes[i].toNumber());
    }
  });

  it('signature verify', async () => {
    const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const hash = sha3_256(payload);
    const signatureO1 = signer.sign(hash);
    const hashO1 = Hash.SHA3_256.hash(Bytes.from(payload));
    const aff = hashToScalar(hashO1);
    const isValid = signatureO1.verifySignedHashV2(aff, signer.pubO1);
    expect(isValid.toBoolean()).toBe(true);
  });

  it('find subarray', async () => {
    // Example usage:
    const haystack = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const needle = new Uint8Array([4, 5, 6]);

    const position = findSubarrayIndex(haystack, needle);
    expect(position).toEqual(3);
  });
});
