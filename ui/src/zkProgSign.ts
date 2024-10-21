import {
  createEcdsaV2,
  createForeignCurveV2,
  Hash,
  Struct,
  ZkProgram,
  Bytes,
  UInt8,
  Crypto,
} from 'o1js';

class Secp256k1 extends createForeignCurveV2(Crypto.CurveParams.Secp256k1) {}
class Ecdsa extends createEcdsaV2(Secp256k1) {}
class Bytes88 extends Bytes(88) {}

export function hashToScalar(hash: Bytes) {
  let x2 = bytesToLimbBE(hash.bytes.slice(0, 10));
  let x1 = bytesToLimbBE(hash.bytes.slice(10, 21));
  let x0 = bytesToLimbBE(hash.bytes.slice(21, 32));

  return new Secp256k1.Scalar.AlmostReduced([x0, x1, x2]);
}

function bytesToLimbBE(bytes_: UInt8[]) {
  let bytes = bytes_.map((x) => x.value);
  let n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}

export class SignedBytes88 extends Struct({
  payload: Bytes88,
  signature: Ecdsa,
}) {
  verify(publicKey: Secp256k1) {
    const hash = Hash.SHA3_256.hash(this.payload);
    const aff = hashToScalar(hash);
    const isValid = this.signature.verifySignedHashV2(aff, publicKey);
    isValid.assertTrue('signature validation failed');
  }
}

export const ZkProgSign = ZkProgram({
  name: 'sign',
  publicInput: Secp256k1,

  methods: {
    verifySign: {
      privateInputs: [SignedBytes88],

      async method(signer: Secp256k1, signed: SignedBytes88) {
        signed.verify(signer);
      },
    },
  },
});
