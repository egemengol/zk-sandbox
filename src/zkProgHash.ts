import { Hash, ZkProgram } from 'o1js';
import { Bytes32, Bytes8 } from './common';

export const ZkProgHash = ZkProgram({
  name: 'hash',
  publicInput: Bytes32,

  methods: {
    verify: {
      privateInputs: [Bytes8],

      async method(hash: Bytes32, payload: Bytes8) {
        const hash_got: Bytes32 = Hash.SHA3_256.hash(payload);
        for (let i = 0; i < 32; i += 1) {
          hash.bytes[i].assertEquals(hash_got.bytes[i]);
        }
      },
    },
  },
});
