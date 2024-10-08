import { Hash, Struct, ZkProgram } from 'o1js';
import { Bytes8, Ecdsa, hashToScalar, Secp256k1 } from './common';

export class SignedBytes8 extends Struct({
  payload: Bytes8,
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
    verify: {
      privateInputs: [SignedBytes8],

      async method(signer: Secp256k1, signed: SignedBytes8) {
        signed.verify(signer);
      },
    },
  },
});
