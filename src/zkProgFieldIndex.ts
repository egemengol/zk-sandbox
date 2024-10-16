import { Bytes, Field, Hash, Provable, Struct, UInt8, ZkProgram } from 'o1js';
import { Bytes32, Bytes8 } from './common';

class Bytes4 extends Bytes(4) {}

class FieldIndexInput extends Struct({
  pos: Field,
  val: UInt8,
}) {}

export const ZkProgFieldIndex = ZkProgram({
  name: 'field-index',
  publicInput: FieldIndexInput,

  methods: {
    verify: {
      privateInputs: [Bytes4],

      async method(inp: FieldIndexInput, arr: Bytes4) {
        inp.val.assertEquals(arr.bytes[inp.pos]);
      },
    },
  },
});
