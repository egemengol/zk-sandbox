import { Bytes, createForeignCurveV2, Crypto, createEcdsaV2 } from 'o1js';

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha3_256 } from '@noble/hashes/sha3';

export class Secp256k1 extends createForeignCurveV2(
  Crypto.CurveParams.Secp256k1
) {}
export class Ecdsa extends createEcdsaV2(Secp256k1) {}
export class Bytes8 extends Bytes(8) {}
export class Bytes32 extends Bytes(32) {}

export class SignerNoble {
  public privNative: Uint8Array;
  public pubNative: Uint8Array;
  public pubO1: Secp256k1;

  constructor() {
    this.privNative = secp256k1.utils.randomPrivateKey();
    this.pubNative = secp256k1.getPublicKey(this.privNative);

    const uncompressedPub = secp256k1.ProjectivePoint.fromHex(
      this.pubNative
    ).toRawBytes(false);
    const xArr = uncompressedPub.slice(1, 33);
    const yArr = uncompressedPub.slice(33);
    const x = BigInt(
      '0x' +
        Array.from(xArr)
          .map((c) => c.toString(16).padStart(2, '0'))
          .join('')
    );
    const y = BigInt(
      '0x' +
        Array.from(yArr)
          .map((c) => c.toString(16).padStart(2, '0'))
          .join('')
    );
    this.pubO1 = new Secp256k1({
      x,
      y,
    });
  }

  sign(payload: Uint8Array): Ecdsa {
    const hash = sha3_256(payload);
    const sig = secp256k1.sign(hash, this.privNative);

    const r = BigInt('0x' + sig.r.toString(16));
    const s = BigInt('0x' + sig.s.toString(16));

    return new Ecdsa({
      r,
      s,
    });
  }
}
