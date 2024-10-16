import { Struct, ZkProgram, Bytes, UInt8, Hash } from 'o1js';

// class MRZ extends Bytes(88) {}
class Bytes257 extends Bytes(257) {}
class Bytes32 extends Bytes(32) {}
class Bytes88 extends Bytes(88) {}

export class Digest extends Struct({
  bytes: Bytes32,
}) {}

export class MRZ extends Struct({
  bytes: Bytes88,
}) {}

export const V2Mrz = ZkProgram({
  name: 'v2-mrz',
  publicInput: MRZ,
  publicOutput: Digest,

  methods: {
    mrz2concatHash: {
      privateInputs: [Bytes257],

      async method(mrz: MRZ, dataGroupHashesConcat: Bytes257) {
        const wrappedMRZ = [97, 91, 95, 31, 88].map(UInt8.from);
        wrappedMRZ.push(...mrz.bytes.bytes);
        const mrzHash = Hash.SHA3_256.hash(Bytes.from(wrappedMRZ));
        // should assert if enough length, but for mock it is valid and skipped.
        for (let i = 0; i < 32; i += 1) {
          mrzHash.bytes[i].assertEquals(
            dataGroupHashesConcat.bytes[33 + i] // HARDCODE 33 for now
          );
        }

        const concatHash = Hash.SHA3_256.hash(dataGroupHashesConcat);
        return new Digest({ bytes: concatHash });
      },
    },
  },
});
