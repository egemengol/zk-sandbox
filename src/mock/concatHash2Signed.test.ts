import { Bytes, verify, VerificationKey } from 'o1js';
import { ConcatHash2Signed } from './concatHash2Signed';
import { JSLand, Mock, O1Land } from './mock';
import { sha3_256 } from '@noble/hashes/sha3';

const MRZ =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

describe('mock', () => {
  let mock: Mock;
  let verificationKey: VerificationKey;

  beforeAll(async () => {
    const program = await ConcatHash2Signed.compile();
    verificationKey = program.verificationKey;
    mock = JSLand.generateMock(MRZ);
  });

  it('validate broad using zkProgram', async () => {
    const publicKey = O1Land.parsePublicKey(mock.publicKey);
    const signature = O1Land.parseSignature(mock.signature);
    const concatHash = sha3_256(mock.dataGroupHashesConcat);
    const proof = await ConcatHash2Signed.prove(publicKey, {
      dataGroupHashesConcatHash: Bytes.from(concatHash),
      signature,
    });
    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);
  });
});
