import { Struct, ZkProgram, Bytes, Provable, UInt8 } from 'o1js';
import { O1Land, Ecdsa, Secp256k1 } from './mock';

class Bytes32 extends Bytes(32) {}
class Bytes88 extends Bytes(88) {}
class Bytes257 extends Bytes(257) {}

export class MrzConcat2ConcatHashPublicInput extends Struct({
  mrz: Bytes88,
  dataGroupHashesConcat: Bytes257,
  dataGroupHashesConcatHash: Bytes32,
}) {}

// function econtentFromConcatHash(concatHash: Bytes): Bytes {
//   const eContent: UInt8[] = [
//     49, 102, 48, 21, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 3, 49, 8, 6, 6,
//     103, -127, 8, 1, 1, 1, 48, 28, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 5,
//     49, 15, 23, 13, 49, 57, 49, 50, 49, 54, 49, 55, 50, 50, 51, 56, 90, 48, 47,
//     6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 4, 49, 34, 4, 32,
//   ].map((n) => UInt8.from(n < 0 ? n + 256 : n));
//   eContent.push(...concatHash.bytes);
//   return Bytes.from(eContent);
// }

// function validateMockBroad(
//   dataGroupConcat: Bytes,
//   signature: Ecdsa,
//   pubkey: Secp256k1
// ) {
//   const concatHash = Hash.SHA3_256.hash(dataGroupConcat);
//   const eContent = econtentFromConcatHash(concatHash);
//   const eContentHash = Hash.SHA3_256.hash(eContent);
//   const aff = hashToScalar(eContentHash);
//   const isValid = signature.verifySignedHashV2(aff, pubkey);
//   isValid.assertTrue('signature validation failed');
// }

export const MrzConcat2ConcatHash = ZkProgram({
  name: 'mrz-concat-2-concat-hash',
  publicInput: Secp256k1,

  methods: {
    prove: {
      privateInputs: [SignedConcatHashInput],

      async method(publicKey: Secp256k1, inp: SignedConcatHashInput) {
        const isValid = O1Land.isValidConcatHash(
          inp.dataGroupHashesConcatHash,
          inp.signature,
          publicKey
        );
        isValid.assertTrue('broad validation failed');
      },
    },
  },
});
