import { verify, VerificationKey, Bytes } from 'o1js';
import { SignedBytes8, ZkProgSign } from './zkProgSign';
import { sha3_256 } from '@noble/hashes/sha3';
import { SignerElliptic } from './common';
// import * as fs from 'fs'; // Add this import

describe('zkProg Sign', () => {
  let verificationKey: VerificationKey;
  let signer: SignerElliptic;

  beforeAll(async () => {
    const program = await ZkProgSign.compile();
    verificationKey = program.verificationKey;
    signer = new SignerElliptic();
  });

  it('verifies a signed bytes8', async () => {
    const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const hash = sha3_256(payload);
    const signatureO1 = signer.sign(hash);

    const signed = new SignedBytes8({
      payload: Bytes.from(payload),
      signature: signatureO1,
    });

    const proof = await ZkProgSign.verify(signer.pubO1, signed);

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
    const signatureO1 = signer.sign(hash);

    payload[1] = 1;
    const signed = new SignedBytes8({
      payload: Bytes.from(payload),
      signature: signatureO1,
    });
    await expect(async () => {
      await ZkProgSign.verify(signer.pubO1, signed);
    }).rejects.toThrow();
  });
});
