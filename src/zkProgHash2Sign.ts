import { Bytes, Hash, Struct, ZkProgram } from 'o1js';
import { Bytes8, Ecdsa, hashToScalar, Secp256k1 } from './common';

class Bytes300 extends Bytes(300) {}

export class SignedPayload extends Struct({
  payload: Bytes300,
  signature: Ecdsa,
}) {
  prove(publicKey: Secp256k1) {
    const hash1 = Hash.SHA3_256.hash(this.payload);
    const hash2 = Hash.SHA3_256.hash(hash1);

    const aff = hashToScalar(hash2);
    const isValid = this.signature.verifySignedHashV2(aff, publicKey);
    isValid.assertTrue('signature validation failed');
  }
}

export const Hash2SignProg = ZkProgram({
  name: 'hash2sign',
  publicInput: Secp256k1,

  methods: {
    prove: {
      privateInputs: [SignedPayload],

      async method(signer: Secp256k1, signed: SignedPayload) {
        signed.prove(signer);
      },
    },
  },
});
