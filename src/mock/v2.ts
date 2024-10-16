import {
  Struct,
  ZkProgram,
  Bytes,
  DynamicProof,
  Void,
  VerificationKey,
} from 'o1js';
import { Ecdsa, Secp256k1 } from './mock';
import { SignedConcatHashInput } from './concatHash2Signed';
import { Digest, MRZ } from './v2Mrz';

class Bytes32 extends Bytes(32) {}

export class V2Input extends Struct({
  signature: Ecdsa,
  publicKey: Secp256k1,
}) {}

export class DynMRZProof extends DynamicProof<MRZ, Digest> {
  static publicInputType = MRZ;
  static publicOutputType = Digest;
  static maxProofsVerified = 0 as const;
}

export class DynSignatureProof extends DynamicProof<
  SignedConcatHashInput,
  Void
> {
  static publicInputType = SignedConcatHashInput;
  static publicOutputType = Void;
  static maxProofsVerified = 0 as const;
}

function assertEqualsBytes32(l: Bytes32, r: Bytes32) {
  for (let i = 0; i < 32; i += 1) {
    l.bytes[i].assertEquals(r.bytes[i]);
  }
}

export const V2 = ZkProgram({
  name: 'v2',
  publicInput: V2Input,

  methods: {
    verifyMock: {
      privateInputs: [
        MRZ,
        VerificationKey,
        DynMRZProof,
        VerificationKey,
        DynSignatureProof,
      ],

      async method(
        inp: V2Input,
        mrz: MRZ,
        vkMRZ: VerificationKey,
        proofMRZ: DynMRZProof,
        vkSign: VerificationKey,
        proofSign: DynSignatureProof
      ) {
        proofMRZ.verify(vkMRZ);
        proofSign.verify(vkSign);

        // // this.mrz == proofMRZ.mrz
        // assertEqualsBytes32(mrz.bytes, proofMRZ.publicInput.bytes);

        // // proofMrz.concatHash == proofSign.concatHash
        // assertEqualsBytes32(
        //   proofMRZ.publicOutput.bytes,
        //   proofSign.publicInput.dataGroupHashesConcatHash
        // );

        // // this.sign == proofSign.sign
        // inp.signature.r.assertEquals(proofSign.publicInput.signature.r);
        // inp.signature.s.assertEquals(proofSign.publicInput.signature.s);

        // // this.pubkey == proofSign.pubkey
        // inp.publicKey.x.assertEquals(proofSign.publicInput.publicKey.x);
        // inp.publicKey.y.assertEquals(proofSign.publicInput.publicKey.y);
      },
    },
  },
});
