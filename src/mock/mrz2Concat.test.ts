import { verify, VerificationKey, Bytes, UInt8 } from 'o1js';
import { MRZ2Concat } from './mrz2Concat';
import { JSLand, Mock } from './mock';

const MRZ =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

describe('MRZ 2 concat', () => {
  let verificationKey: VerificationKey;
  let mock: Mock;

  beforeAll(async () => {
    const program = await MRZ2Concat.compile();
    verificationKey = program.verificationKey;
    mock = JSLand.generateMock(MRZ);
  });

  it('prove hardcoded offset', async () => {
    const proof = await MRZ2Concat.prove({
      mrz: Bytes.from(
        [...mock.mrz].map((char) => UInt8.from(char.charCodeAt(0)))
      ),
      dataGroupHashesConcat: Bytes.from(mock.dataGroupHashesConcat),
    });

    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);
  });
});
