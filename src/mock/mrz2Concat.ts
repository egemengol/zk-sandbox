import { Struct, ZkProgram, Bytes, UInt8, Hash } from 'o1js';

class MRZ extends Bytes(88) {}
class Bytes257 extends Bytes(257) {}

export class Mrz2ConcatInput extends Struct({
  mrz: MRZ,
  dataGroupHashesConcat: Bytes257,
  // position: Field, HARDCODE 33
}) {}

export const MRZ2Concat = ZkProgram({
  name: 'mrz-2-concat',
  publicInput: Mrz2ConcatInput,

  methods: {
    prove: {
      privateInputs: [],

      async method(inp: Mrz2ConcatInput) {
        const wrappedMRZ = [97, 91, 95, 31, 88].map(UInt8.from);
        wrappedMRZ.push(...inp.mrz.bytes);
        const mrzHash = Hash.SHA3_256.hash(Bytes.from(wrappedMRZ));
        // should assert if enough length, but for mock it is valid and skipped.
        for (let i = 0; i < 32; i += 1) {
          mrzHash.bytes[i].assertEquals(
            inp.dataGroupHashesConcat.bytes[33 + i] // HARDCODE 33 for now
          );
        }
      },
    },
  },
});
