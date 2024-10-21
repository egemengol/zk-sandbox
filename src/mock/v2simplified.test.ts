import {
  VerificationKey,
  Bytes,
  DynamicProof,
  Void,
  Proof,
  verify,
  UInt8,
} from 'o1js';
import { JSLand, Mock, O1Land } from './mock';
import { sha3_256 } from '@noble/hashes/sha3';
import { ConcatHash2Signed, SignedConcatHashInput } from './concatHash2Signed';
import { DynMRZProof, V2Simplified } from './v2simplified';
import { MRZ, V2Mrz } from './v2Mrz';

const MRZ_SAMPLE =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

describe('V2', () => {
  let vkMRZ: VerificationKey;
  let vk: VerificationKey;
  let mock: Mock;

  beforeAll(async () => {
    vkMRZ = (await V2Mrz.compile()).verificationKey;
    // vkSign = (await ConcatHash2Signed.compile()).verificationKey;
    vk = (await V2Simplified.compile()).verificationKey;
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

    expect(await verify(dynProofMRZ, vkMRZ)).toBe(true);
    // console.log('122');
    // dynProofMRZ.verify(vkMRZ);
    // console.log('123');
    // dynProofMRZ.verify(vkMRZ);
    // dynProofMRZ.verify(vkMRZ);

    console.log('123');

    const proofFinal = await V2Simplified.verifyMock(vkMRZ, dynProofMRZ);

    console.log('124');
    // expect(await V2Simplified.verify(proofFinal)).toBe(true);
  });
});
