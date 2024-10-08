import { Bytes, Hash } from 'o1js';
import { sha3_256 } from '@noble/hashes/sha3';
import { Bytes32, SignerElliptic, hashToScalar } from './common';

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
});
