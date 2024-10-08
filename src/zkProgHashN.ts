import { Hash, ZkProgram } from 'o1js';
import { Bytes32, Bytes8 } from './common';

export const ZkProgHashN = ZkProgram({
  name: 'hashN',
  publicInput: Bytes32,

  methods: {
    verify: {
      privateInputs: [Bytes8],

      async method(hash: Bytes32, payload: Bytes8) {
        const hash_1: Bytes32 = Hash.SHA3_256.hash(payload);
        const hash_2: Bytes32 = Hash.SHA3_256.hash(hash_1);
        const hash_3: Bytes32 = Hash.SHA3_256.hash(hash_2);
        const hash_4: Bytes32 = Hash.SHA3_256.hash(hash_3);
        const hash_5: Bytes32 = Hash.SHA3_256.hash(hash_4);
        for (let i = 0; i < 32; i += 1) {
          hash.bytes[i].assertEquals(hash_5.bytes[i]);
        }
      },
    },
  },
});
