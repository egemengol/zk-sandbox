import { verify, VerificationKey, Bytes } from 'o1js';
import { SignedPayload, Hash2SignProg } from './zkProgHash2Sign';
import { sha3_256 } from '@noble/hashes/sha3';
import { SignerElliptic } from './common';
// import * as fs from 'fs'; // Add this import

function generateSignedPayload(signer: SignerElliptic) {
  const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);

  const hash1 = sha3_256(payload);
  const hash2 = sha3_256(hash1);
  const signatureO1 = signer.sign(hash2);

  const signed = new SignedPayload({
    payload: Bytes.from(payload),
    signature: signatureO1,
  });

  return signed;
}

describe('zkProg Hash2Sign', () => {
  let verificationKey: VerificationKey;
  let signer: SignerElliptic;
  let signed: SignedPayload;

  beforeAll(async () => {
    const program = await Hash2SignProg.compile();
    verificationKey = program.verificationKey;
    signer = new SignerElliptic();
    signed = generateSignedPayload(signer);
  });

  it('proves a signed', async () => {
    const proof = await Hash2SignProg.prove(signer.pubO1, signed);

    // fs.writeFileSync(
    //   'proof.json',
    //   JSON.stringify(proof.toJSON(), null, 2),
    //   'utf8'
    // );

    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);
  });
});
