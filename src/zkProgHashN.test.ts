import { verify, VerificationKey, Bytes } from 'o1js';
import { ZkProgHashN } from './zkProgHashN';
import { sha3_256 } from '@noble/hashes/sha3';
// import * as fs from 'fs'; // Add this import

describe.skip('zkProg Hash N', () => {
  let verificationKey: VerificationKey;

  beforeAll(async () => {
    const program = await ZkProgHashN.compile();
    verificationKey = program.verificationKey;
  });

  it('verifies a hash N', async () => {
    const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
    let hash = payload;
    for (let i = 0; i < 5; i += 1) {
      hash = sha3_256(hash);
    }
    const proof = await ZkProgHashN.verify(
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
});
