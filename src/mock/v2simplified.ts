import { ZkProgram, DynamicProof, VerificationKey } from 'o1js';
import { Digest, MRZ } from './v2Mrz';

export class DynMRZProof extends DynamicProof<MRZ, Digest> {
  static publicInputType = MRZ;
  static publicOutputType = Digest;
  static maxProofsVerified = 0 as const;
}

export const V2Simplified = ZkProgram({
  name: 'v2-simplified',

  methods: {
    verifyMock: {
      privateInputs: [VerificationKey, DynMRZProof],

      async method(vkMRZ: VerificationKey, proofMRZ: DynMRZProof) {
        proofMRZ.verify(vkMRZ);
      },
    },
  },
});
