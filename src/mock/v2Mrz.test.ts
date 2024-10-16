import { verify, VerificationKey, Bytes, UInt8 } from 'o1js';
import { V2Mrz, MRZ } from './v2Mrz';
import { JSLand, Mock } from './mock';
import { sha3_256 } from '@noble/hashes/sha3';

const MRZ_SAMPLE =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

describe('V2 MRZ to concatHash', () => {
  let verificationKey: VerificationKey;
  let mock: Mock;

  beforeAll(async () => {
    const program = await V2Mrz.compile();
    verificationKey = program.verificationKey;
    mock = JSLand.generateMock(MRZ_SAMPLE);
  });

  it('prove hardcoded offset', async () => {
    const proof = await V2Mrz.mrz2concatHash(
      new MRZ({
        bytes: Bytes.from(
          [...mock.mrz].map((char) => UInt8.from(char.charCodeAt(0)))
        ),
      }),
      Bytes.from(mock.dataGroupHashesConcat)
    );
    // console.log(proof);

    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);

    expect(proof.publicOutput.bytes.toBytes()).toEqual(
      sha3_256(mock.dataGroupHashesConcat)
    );
  });
});
