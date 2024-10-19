import { VerificationKey, Bytes, UInt8, Proof } from 'o1js';
import { V2Mrz, MRZ, Digest } from './v2Mrz';
import { JSLand, Mock, O1Land } from './mock';
import { sha3_256 } from '@noble/hashes/sha3';
import { DynMRZProof, DynSignatureProof, V2 } from './v2';
import { ConcatHash2Signed, SignedConcatHashInput } from './concatHash2Signed';
import * as fs from 'fs';

const MRZ_SAMPLE =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

// let VK_MRZ: VerificationKey

// class ProofMRZ extends Proof<MRZ, Digest> {}

// async function getProofMRZ(mock: Mock): Promise<ProofMRZ> {
//   const proofPath = './mrz.proof.json';
//   if (fs.existsSync(proofPath)) {
//     const serialized = fs.readFileSync(proofPath, 'utf8');
//     return await ProofMRZ.fromJSON(JSON.parse(serialized));
//   } else {
//     console.log('compiling mrz proof');
//     await V2Mrz.compile();
//     const mrzStruct = new MRZ({
//       bytes: Bytes.from(
//         [...mock.mrz].map((char) => UInt8.from(char.charCodeAt(0)))
//       ),
//     });
//     const proof = await V2Mrz.mrz2concatHash(
//       mrzStruct,
//       Bytes.from(mock.dataGroupHashesConcat)
//     );
//     fs.writeFileSync(proofPath, JSON.stringify(proof.toJSON()));
//     return proof;
//   }
// }

// class ProofSign extends Proof<SignedConcatHashInput, void> {}

// async function getProofSign(mock: Mock): Promise<ProofSign> {
//   const proofPath = './sign.proof.json';
//   if (fs.existsSync(proofPath)) {
//     const serialized = fs.readFileSync(proofPath, 'utf8');
//     return await ProofSign.fromJSON(JSON.parse(serialized));
//   } else {
//     console.log('compiling sign proof');
//     await ConcatHash2Signed.compile();
//     const publicKey = O1Land.parsePublicKey(mock.publicKey);
//     const signature = O1Land.parseSignature(mock.signature);
//     const concatHash = sha3_256(mock.dataGroupHashesConcat);
//     const proof = await ConcatHash2Signed.prove({
//       publicKey,
//       dataGroupHashesConcatHash: Bytes.from(concatHash),
//       signature,
//     });
//     fs.writeFileSync(proofPath, JSON.stringify(proof.toJSON()));
//     return proof;
//   }
// }
/*
async function getProofs(mock: Mock): [DynMRZProof, DynSignatureProof] {
  const signProofPath = './sign.proof.json';
  let proofMRZ: Proof<MRZ, Digest>;
  let proofSign: Proof<SignedConcatHashInput, void>;

  if (true ) {
    await V2Mrz.compile();
    await ConcatHash2Signed.compile();
    const concatHash = sha3_256(mock.dataGroupHashesConcat);
    const mrzStruct = new MRZ({
      bytes: Bytes.from(
        [...mock.mrz].map((char) => UInt8.from(char.charCodeAt(0)))
      ),
    });
    proofMRZ = await V2Mrz.mrz2concatHash(
      mrzStruct,
      Bytes.from(mock.dataGroupHashesConcat)
    );

    const publicKey = O1Land.parsePublicKey(mock.publicKey);
    const signature = O1Land.parseSignature(mock.signature);
    const proofSign = await ConcatHash2Signed.prove({
      publicKey,
      dataGroupHashesConcatHash: Bytes.from(concatHash),
      signature,
    });
    expect(await ConcatHash2Signed.verify(proofSign)).toBe(true);
    const dynProofSign = DynSignatureProof.fromProof(proofSign);

    const proofMRZSerialized = JSON.stringify(proofMRZ.toJSON());
    const dynProofMRZ = DynMRZProof.fromProof(proofMRZ);
  } else {
    // read file into proofs
  }
  return [
    DynMRZProof.fromProof(proofMRZ),
    DynSignatureProof.fromProof(proofSign),
  ];
}
*/

describe('V2', () => {
  let vkMRZ: VerificationKey;
  let vkSign: VerificationKey;
  let vk: VerificationKey;
  let mock: Mock;

  beforeAll(async () => {
    vkMRZ = (await V2Mrz.compile()).verificationKey;
    vkSign = (await ConcatHash2Signed.compile()).verificationKey;
    vk = (await V2.compile()).verificationKey;
    // vk.data.toString()
    // console.log(vk.toJSON());
    mock = JSLand.generateMock(MRZ_SAMPLE);
  });

  it('prove hardcoded offset', async () => {
    const concatHash = sha3_256(mock.dataGroupHashesConcat);
    const mrzStruct = new MRZ({
      bytes: Bytes.from(
        [...mock.mrz].map((char) => UInt8.from(char.charCodeAt(0)))
      ),
    });
    const proofMRZ = await V2Mrz.mrz2concatHash(
      mrzStruct,
      Bytes.from(mock.dataGroupHashesConcat)
    );
    expect(await V2Mrz.verify(proofMRZ)).toBe(true);
    expect(proofMRZ.publicOutput.bytes.toBytes()).toEqual(concatHash);
    const dynProofMRZ = DynMRZProof.fromProof(proofMRZ);

    const publicKey = O1Land.parsePublicKey(mock.publicKey);
    const signature = O1Land.parseSignature(mock.signature);
    const proofSign = await ConcatHash2Signed.prove({
      publicKey,
      dataGroupHashesConcatHash: Bytes.from(concatHash),
      signature,
    });
    expect(await ConcatHash2Signed.verify(proofSign)).toBe(true);
    const dynProofSign = DynSignatureProof.fromProof(proofSign);

    // const mrzStruct = new MRZ({
    //   bytes: Bytes.from(
    //     [...mock.mrz].map((char) => UInt8.from(char.charCodeAt(0)))
    //   ),
    // });
    // const publicKey = O1Land.parsePublicKey(mock.publicKey);
    // const signature = O1Land.parseSignature(mock.signature);
    // const dynProofMRZ = DynMRZProof.fromProof(await getProofMRZ(mock));
    // const dynProofSign = DynSignatureProof.fromProof(await getProofSign(mock));

    // final proof
    const proofFinal = await V2.verifyMock(
      // { signature, publicKey },
      // mrzStruct,
      // vkMRZ,
      // dynProofMRZ
      vkSign,
      dynProofSign
    );
    expect(await V2.verify(proofFinal)).toBe(true);
  });
});
