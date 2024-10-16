import { Struct, ZkProgram, Bytes, Hash } from 'o1js';

class Bytes257 extends Bytes(257) {}
class Bytes32 extends Bytes(32) {}

export class Concat2ConcatHashInput extends Struct({
  dataGroupHashesConcat: Bytes257,
  hash: Bytes32,
}) {}

export const Concat2ConcatHash = ZkProgram({
  name: 'concat-2-concat-hash',
  publicInput: Concat2ConcatHashInput,

  methods: {
    prove: {
      privateInputs: [],

      async method(inp: Concat2ConcatHashInput) {
        const gotHash = Hash.SHA3_256.hash(inp.dataGroupHashesConcat);
        for (let i = 0; i < 32; i++) {
          gotHash.bytes[i].assertEquals(inp.hash.bytes[i]);
        }
      },
    },
  },
});
