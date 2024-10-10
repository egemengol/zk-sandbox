import { verify, VerificationKey, Bytes } from 'o1js';
import { ZkProgHash } from './zkProgHash';
import { sha3_256 } from '@noble/hashes/sha3';
// import * as fs from 'fs'; // Add this import

describe.skip('zkProg Hash', () => {
  let verificationKey: VerificationKey;

  beforeAll(async () => {
    const program = await ZkProgHash.compile();
    verificationKey = program.verificationKey;
  });

  it('verifies a hash', async () => {
    const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const hash = sha3_256(payload);
    const proof = await ZkProgHash.verify(
      Bytes.from(hash),
      Bytes.from(payload)
    );

    // fs.writeFileSync(
    //   'proof.json',
    //   JSON.stringify(proof.toJSON(), null, 2),
    //   'utf8'
    // );

    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);
  });

  it('does not verify invalid hash', async () => {
    const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const hash = sha3_256(payload);
    await expect(async () => {
      payload[1] = 1;
      await ZkProgHash.verify(Bytes.from(hash), Bytes.from(payload));
    }).rejects.toThrow();
  });
});
