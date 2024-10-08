import { verify, Bytes } from 'o1js';
import { Layered, ZkProgLayered } from './zkProgLayered';
import { sha3_256 } from '@noble/hashes/sha3';
import { SignerElliptic } from './common';

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

async function main() {
  const program = await ZkProgLayered.compile();
  console.log('compiled');
  const verificationKey = program.verificationKey;
  const signer = new SignerElliptic();
  const layered = generateLayered(signer);

  const proof = await ZkProgLayered.verify(signer.pubO1, layered);
  console.log('created proof');
  const isSolution = await verify(proof.toJSON(), verificationKey);
  console.log(isSolution);
}

main();
