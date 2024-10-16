import { Struct, ZkProgram, Bytes } from 'o1js';
import { O1Land, Ecdsa, Secp256k1 } from './mock';

class Bytes32 extends Bytes(32) {}

export class SignedConcatHashInput extends Struct({
  dataGroupHashesConcatHash: Bytes32,
  signature: Ecdsa,
  publicKey: Secp256k1,
}) {}

export const ConcatHash2Signed = ZkProgram({
  name: 'concat-hash-2-signed',
  publicInput: SignedConcatHashInput,

  methods: {
    prove: {
      privateInputs: [],

      async method(inp: SignedConcatHashInput) {
        const isValid = O1Land.isValidConcatHash(
          inp.dataGroupHashesConcatHash,
          inp.signature,
          inp.publicKey
        );
        isValid.assertTrue('broad validation failed');
      },
    },
  },
});
