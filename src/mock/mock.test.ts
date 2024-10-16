import { Bytes } from 'o1js';
import { JSLand, Mock, O1Land } from './mock';
import { sha3_256 } from '@noble/hashes/sha3';

const MRZ =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

describe('mock common', () => {
  let mock: Mock;

  beforeAll(() => {
    mock = JSLand.generateMock(MRZ);
  });

  it('generates and validates in jsland', () => {
    expect(
      JSLand.isValidBroad(
        mock.dataGroupHashesConcat,
        mock.signature,
        mock.publicKey
      )
    ).toEqual(true);
  });

  it('generates and validates in o1land', () => {
    console.log(mock.dataGroupHashesConcat.length);
    const concatHash = sha3_256(mock.dataGroupHashesConcat);
    expect(
      O1Land.isValidConcatHash(
        Bytes.from(concatHash),
        O1Land.parseSignature(mock.signature),
        O1Land.parsePublicKey(mock.publicKey)
      ).assertTrue()
    );
  });
});
