import { Bytes, Hash, Provable, Struct, UInt8 } from 'o1js';
import { Bytes32 } from './common';

export class PassportData extends Struct({
  mrz: Provable.Array(UInt8, 88),
}) {
  hashMRZ(): Bytes32 {
    /*
      97: DG1 tag
      91: len of right
      95, 31: MRZ_INFO_TAG
      88: len of right == len mrz
    */
    // DG1_tag, len->, MRZ_INFO_TAG,
    const header = [97, 91, 95, 31, 88].map(UInt8.from);
    const hashInput = Bytes.from(header.concat(this.mrz));
    const hashResult: Bytes32 = Hash.SHA3_256.hash(hashInput);
    return hashResult;
  }
}
