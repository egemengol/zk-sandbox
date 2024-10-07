import {
  Bytes,
  assert,
  createForeignCurveV2,
  ForeignCurveV2,
  UInt8,
  Crypto,
  createEcdsaV2,
  AlmostForeignField,
  Gadgets,
} from 'o1js';

// const { Field3 } = Gadgets;
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha3_256 } from '@noble/hashes/sha3';
import elliptic from 'elliptic';

export class Secp256k1 extends createForeignCurveV2(
  Crypto.CurveParams.Secp256k1
) {}
export class Ecdsa extends createEcdsaV2(Secp256k1) {}
export class Bytes8 extends Bytes(8) {}
export class Bytes32 extends Bytes(32) {}

// export function bytesToLimbBE(bytes_: UInt8[]) {
//   let bytes = bytes_.map((x) => x.value);
//   let n = bytes.length;
//   let limb = bytes[0];
//   for (let i = 1; i < n; i++) {
//     limb = limb.mul(1n << 8n).add(bytes[i]);
//   }
//   return limb.seal();
// }

// export function keccakOutputToScalar(hash: Bytes): Field3 {
//   let x2 = bytesToLimbBE(hash.bytes.slice(0, 10));
//   let x1 = bytesToLimbBE(hash.bytes.slice(10, 21));
//   let x0 = bytesToLimbBE(hash.bytes.slice(21, 32));

//   return [x0, x1, x2];
// }

class SignerNoble {
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
    const x = BigInt('0x' + Buffer.from(xArr).toString('hex'));
    const y = BigInt('0x' + Buffer.from(yArr).toString('hex'));
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

class SignerElliptic {
  static eCurve = new elliptic.ec('secp256k1');

  public keyPairNative: elliptic.ec.KeyPair;
  public privHex: string;
  public pub: elliptic.curve.base.BasePoint;
  public pubO1: Secp256k1;

  constructor() {
    this.keyPairNative = SignerElliptic.eCurve.genKeyPair();
    this.privHex = this.keyPairNative.getPrivate('hex');
    this.pub = this.keyPairNative.getPublic();

    this.pubO1 = new Secp256k1({
      x: BigInt(this.pub.getX().toString()),
      y: BigInt(this.pub.getY().toString()),
    });
  }

  sign(payload: Uint8Array): Ecdsa {
    const signed = SignerElliptic.eCurve.sign(payload, this.keyPairNative);
    return new Ecdsa({
      r: BigInt(signed.r.toString()),
      s: BigInt(signed.s.toString()),
    });
  }
}
