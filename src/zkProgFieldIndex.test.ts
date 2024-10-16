import { verify, VerificationKey, Bytes, UInt8, Field } from 'o1js';
import { ZkProgFieldIndex } from './zkProgFieldIndex';

describe('zkProg Field Index', () => {
  let verificationKey: VerificationKey;

  beforeAll(async () => {
    const program = await ZkProgFieldIndex.compile();
    verificationKey = program.verificationKey;
  });

  it('proves a signed', async () => {
    const arr = Bytes.from([3, 4, 5, 6]);
    const proof = await ZkProgFieldIndex.verify(
      {
        pos: Field(2),
        val: UInt8.from(5),
      },
      arr
    );

    const isSolution = await verify(proof.toJSON(), verificationKey);
    expect(isSolution).toBe(true);
  });
});
