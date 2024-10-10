import { verify, VerificationKey, Bytes } from 'o1js';
import { Layered, ZkProgLayered } from './zkProgLayered';
import { sha3_256 } from '@noble/hashes/sha3';
import { SignerElliptic } from './common';
// import * as fs from 'fs'; // Add this import

function generateLayered(signer: SignerElliptic) {
  const zone1Fields = [
    new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]),
    new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]),
    new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]),
  ];
  const zone2 = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);

  const hash1 = sha3_256(
    new Uint8Array(Buffer.concat(zone1Fields.map((arr) => Buffer.from(arr))))
  );
  const hash2 = sha3_256(zone2);

  const hashAggr = sha3_256(new Uint8Array(Buffer.concat([hash1, hash2])));

  const signatureO1 = signer.sign(hashAggr);

  const layered = new Layered({
    zone1: zone1Fields.map((f) => Bytes.from(f)),
    zone2: Bytes.from(zone2),
    signature: signatureO1,
  });

  return layered;
}

describe.skip('zkProg Layered', () => {
  let verificationKey: VerificationKey;
  let signer: SignerElliptic;
  let layered: Layered;

  beforeAll(async () => {
    const program = await ZkProgLayered.compile();
    verificationKey = program.verificationKey;
    signer = new SignerElliptic();
    layered = generateLayered(signer);
  });

  it('verifies a layered', async () => {
    const proof = await ZkProgLayered.verify(signer.pubO1, layered);

    // fs.writeFileSync(
    //   'proof.json',
    //   JSON.stringify(proof.toJSON(), null, 2),
    //   'utf8'
    // );

    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);
  });

  // it('does not verify invalid hash', async () => {
  //   const payload = new Uint8Array([1, 0, 0, 0, 0, 0, 0, 0]);
  //   const hash = sha3_256(payload);
  //   const signatureO1 = signer.sign(hash);

  //   payload[1] = 1;
  //   const signed = new SignedBytes8({
  //     payload: Bytes.from(payload),
  //     signature: signatureO1,
  //   });
  //   await expect(async () => {
  //     await ZkProgSign.verify(signer.pubO1, signed);
  //   }).rejects.toThrow();
  // });
});
