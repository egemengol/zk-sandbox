import { Bytes, Hash, Provable, Struct, UInt8, ZkProgram } from 'o1js';
import { Bytes8, Ecdsa, hashToScalar, Secp256k1 } from './common';

export class Layered extends Struct({
  zone1: Provable.Array(Bytes8, 3),
  zone2: Bytes8,
  signature: Ecdsa,
}) {
  verify(publicKey: Secp256k1) {
    const zone1Bytes: UInt8[] = [];
    for (const zoneField of this.zone1) {
      zone1Bytes.push(...zoneField.bytes);
    }
    const hash1 = Hash.SHA3_256.hash(Bytes.from(zone1Bytes));

    const hash2 = Hash.SHA3_256.hash(this.zone2);

    // zone hashes get concatenated and hashed again.
    const aggrBytes: UInt8[] = hash1.bytes;
    aggrBytes.push(...hash2.bytes);
    const hashAggr = Hash.SHA3_256.hash(Bytes.from(aggrBytes));

    const aff = hashToScalar(hashAggr);
    const isValid = this.signature.verifySignedHashV2(aff, publicKey);
    isValid.assertTrue('signature validation failed');
  }
}

export const ZkProgLayered = ZkProgram({
  name: 'layered',
  publicInput: Secp256k1,

  methods: {
    verify: {
      privateInputs: [Layered],

      async method(signer: Secp256k1, signed: Layered) {
        signed.verify(signer);
      },
    },
  },
});
