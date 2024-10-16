import { sha3_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  Bytes,
  createForeignCurveV2,
  UInt8,
  Crypto,
  createEcdsaV2,
  Bool,
  Hash,
} from 'o1js';

export class Secp256k1 extends createForeignCurveV2(
  Crypto.CurveParams.Secp256k1
) {}
export class Ecdsa extends createEcdsaV2(Secp256k1) {}

export interface Mock {
  mrz: string;
  dataGroupHashesConcat: Uint8Array;
  signature: Uint8Array;
  publicKey: Uint8Array;
}

export class O1Land {
  static serializeMRZ(mrz: string): UInt8[] {
    const formatted = [97, 91, 95, 31, 88].map(UInt8.from);
    const mrzAscii = [...mrz].map((char) => UInt8.from(char.charCodeAt(0)));
    for (const c of mrzAscii) {
      formatted.push(c);
    }
    return formatted;
  }

  static formattedMRZ(mrz: string): UInt8[] {
    const formatted = [97, 91, 95, 31, 88].map(UInt8.from);
    const mrzAscii = [...mrz].map((char) => UInt8.from(char.charCodeAt(0)));
    for (const c of mrzAscii) {
      formatted.push(c);
    }
    return formatted;
  }

  static parseSignature(signature: Uint8Array): Ecdsa {
    const sig = secp256k1.Signature.fromDER(signature);

    const r = BigInt('0x' + sig.r.toString(16));
    const s = BigInt('0x' + sig.s.toString(16));

    return new Ecdsa({
      r,
      s,
    });
  }

  static parsePublicKey(publicKey: Uint8Array): Secp256k1 {
    const uncompressedPub =
      secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
    const xArr = uncompressedPub.slice(1, 33);
    const yArr = uncompressedPub.slice(33);
    const x = BigInt('0x' + Buffer.from(xArr).toString('hex'));
    const y = BigInt('0x' + Buffer.from(yArr).toString('hex'));
    return new Secp256k1({
      x,
      y,
    });
  }

  static eContent(dataGroupHashesConcatHash: UInt8[]): Bytes {
    const bytes = E_CONTENT_HEADER.map((n) => UInt8.from(n < 0 ? n + 256 : n));
    bytes.push(...dataGroupHashesConcatHash);
    return Bytes.from(bytes);
  }

  static hashToScalar(hash: Bytes) {
    let x2 = bytesToLimbBE(hash.bytes.slice(0, 10));
    let x1 = bytesToLimbBE(hash.bytes.slice(10, 21));
    let x0 = bytesToLimbBE(hash.bytes.slice(21, 32));

    return new Secp256k1.Scalar.AlmostReduced([x0, x1, x2]);
  }

  static isValidConcatHash(
    dataGroupHashesConcatHash: Bytes,
    signature: Ecdsa,
    publicKey: Secp256k1
  ): Bool {
    const eContent = O1Land.eContent(dataGroupHashesConcatHash.bytes);
    const eContentHash = Hash.SHA3_256.hash(eContent);
    const aff = O1Land.hashToScalar(eContentHash);
    const isValid = signature.verifySignedHashV2(aff, publicKey);
    // isValid.assertTrue('signature validation failed');
    return isValid;
  }
}

export class JSLand {
  static formattedMRZ(mrz: string): Uint8Array {
    const mrzCharcodes = [...mrz].map((char) => char.charCodeAt(0));
    return Uint8Array.from([97, 91, 95, 31, 88, ...mrzCharcodes]);
  }

  static dataGroupHashesConcat(mrzHash: Uint8Array): Uint8Array {
    const concatenatedDataHashes: number[] = [];
    // write 33 random numbers
    const startingSequence = Array.from(
      { length: 33 },
      () => Math.floor(Math.random() * 256) - 128
    );
    concatenatedDataHashes.push(...startingSequence);
    // write mrz hash
    concatenatedDataHashes.push(...mrzHash);
    // write sample hashes
    for (const datahashTuple of SAMPLE_DATA_HASHES) {
      concatenatedDataHashes.push(...datahashTuple);
    }
    return Uint8Array.from(concatenatedDataHashes);
  }

  static eContent(dataGroupHashesConcatHash: Uint8Array): Uint8Array {
    return Uint8Array.from([
      ...E_CONTENT_HEADER,
      ...Array.from(dataGroupHashesConcatHash),
    ]);
  }

  static generateMock(mrz: string): Mock {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = secp256k1.getPublicKey(privateKey);
    const mrzHash = sha3_256(JSLand.formattedMRZ(mrz));
    const dataGroupHashesConcat = JSLand.dataGroupHashesConcat(mrzHash);
    const dataGroupHashesConcatHash = sha3_256(dataGroupHashesConcat);
    const eContent = JSLand.eContent(dataGroupHashesConcatHash);
    const eContentHash = sha3_256(eContent);
    const signature = secp256k1.sign(eContentHash, privateKey);
    const signatureSerialized = signature.toDERRawBytes();
    return {
      mrz,
      dataGroupHashesConcat,
      signature: signatureSerialized,
      publicKey,
    };
  }

  static isValidBroad(
    dataGroupHashesConcat: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    const dataGroupHashesConcatHash = sha3_256(dataGroupHashesConcat);
    const eContent = JSLand.eContent(dataGroupHashesConcatHash);
    const eContentHash = sha3_256(eContent);
    return secp256k1.verify(signature, eContentHash, publicKey);
  }
}

const SAMPLE_DATA_HASHES = [
  [
    -66, 82, -76, -21, -34, 33, 79, 50, -104, -120, -114, 35, 116, -32, 6, -14,
    -100, -115, -128, -8, 10, 61, 98, 86, -8, 45, -49, -46, 90, -24, -81, 38,
  ],
  [
    0, -62, 104, 108, -19, -10, 97, -26, 116, -58, 69, 110, 26, 87, 17, 89, 110,
    -57, 108, -6, 36, 21, 39, 87, 110, 102, -6, -43, -82, -125, -85, -82,
  ],
  [
    -120, -101, 87, -112, 111, 15, -104, 127, 85, 25, -102, 81, 20, 58, 51, 75,
    -63, 116, -22, 0, 60, 30, 29, 30, -73, -115, 72, -9, -1, -53, 100, 124,
  ],
  [
    41, -22, 106, 78, 31, 11, 114, -119, -19, 17, 92, 71, -122, 47, 62, 78, -67,
    -23, -55, -42, 53, 4, 47, -67, -55, -123, 6, 121, 34, -125, 64, -114,
  ],
  [
    91, -34, -46, -63, 62, -34, 104, 82, 36, 41, -118, -3, 70, 15, -108, -48,
    -100, 45, 105, -85, -15, -61, -71, 43, -39, -94, -110, -55, -34, 89, -18,
    38,
  ],
  [
    76, 123, -40, 13, 51, -29, 72, -11, 59, -63, -18, -90, 103, 49, 23, -92,
    -85, -68, -62, -59, -100, -69, -7, 28, -58, 95, 69, 15, -74, 56, 54, 38,
  ],
];

const E_CONTENT_HEADER = [
  49, 102, 48, 21, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 3, 49, 8, 6, 6, 103,
  -127, 8, 1, 1, 1, 48, 28, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 5, 49, 15,
  23, 13, 49, 57, 49, 50, 49, 54, 49, 55, 50, 50, 51, 56, 90, 48, 47, 6, 9, 42,
  -122, 72, -122, -9, 13, 1, 9, 4, 49, 34, 4, 32,
];

function bytesToLimbBE(bytes_: UInt8[]) {
  let bytes = bytes_.map((x) => x.value);
  let n = bytes.length;
  let limb = bytes[0];
  for (let i = 1; i < n; i++) {
    limb = limb.mul(1n << 8n).add(bytes[i]);
  }
  return limb.seal();
}
