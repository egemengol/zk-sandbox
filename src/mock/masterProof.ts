import { Struct, ZkProgram, Bytes, UInt8, Hash, Proof, verify } from 'o1js';
import { Ecdsa, Secp256k1 } from './mock';
import { MRZ2Concat, Mrz2ConcatInput } from './mrz2Concat';
import { ConcatHash2Signed } from './concatHash2Signed';
import { Concat2ConcatHash } from './concat2ConcatHash';

class MRZ extends Bytes(88) {}
class Bytes32 extends Bytes(32) {}
class Bytes257 extends Bytes(257) {}

const MRZ2ConcatProof = ZkProgram.Proof(MRZ2Concat);
const Concat2ConcatHashProof = ZkProgram.Proof(Concat2ConcatHash);
const ConcatHash2SignedProof = ZkProgram.Proof(ConcatHash2Signed);

export class MockProvePublicInput extends Struct({
  publicKey: Secp256k1,
  mrz2ConcatProof: MRZ2ConcatProof,
  concat2ConcatHashProof: Concat2ConcatHashProof,
  concatHash2SignedProof: ConcatHash2SignedProof,
}) {}

export class MockProvePrivateInput extends Struct({
  mrz: MRZ,
  dataGroupHashesConcat: Bytes257,
  dataGroupHashesConcatHash: Bytes32,
  signature: Ecdsa,
}) {}

export const MockProve = ZkProgram({
  name: 'mock-prove',
  publicInput: MockProvePublicInput,

  methods: {
    prove: {
      privateInputs: [MockProvePrivateInput],

      async method(pub: MockProvePublicInput, pri: MockProvePrivateInput) {
        const proof: MRZ2ConcatProof = pub.mrz2ConcatProof;
      },
    },
  },
});
