import { assembleEContent, sampleDataHashes_large } from './openpassportUtils';
import { sha3_256 } from '@noble/hashes/sha3';
import { PassportData } from './pass';
import { Ecdsa, hashToScalar, Secp256k1, strToAscii } from './common';
import { SignerNoble, arrayEquals, findSubarrayIndex } from './common';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as fs from 'fs';
import { Bytes, UInt8, Hash, assert } from 'o1js';

const MRZ_SAMPLE =
  'P<FRADUPONT<<ALPHONSE<HUGUES<ALBERT<<<<<<<<<24HB818324FRA0402111M3111115<<<<<<<<<<<<<<02';

interface PassportMock {
  mrz: string;
  dataGroupConcat: Uint8Array;
  eContent: Uint8Array;
  encryptedDigest: Uint8Array;
}
function stringifyPassportMock(mock: PassportMock): string {
  return JSON.stringify({
    mrz: mock.mrz,
    dataGroupConcat: Array.from(mock.dataGroupConcat),
    eContent: Array.from(mock.eContent),
    encryptedDigest: Array.from(mock.encryptedDigest),
  });
}

export function formatMrz(mrz: string): Uint8Array {
  const mrzCharcodes = [...mrz].map((char) => char.charCodeAt(0));
  return Uint8Array.from([97, 91, 95, 31, 88, ...mrzCharcodes]);
}

function preparePassport(signer: SignerNoble, mrz: string): PassportMock {
  const mrzHash = sha3_256(formatMrz(mrz));

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
  for (const datahashTuple of sampleDataHashes_large) {
    concatenatedDataHashes.push(...datahashTuple[1]);
  }

  const aggregateHash = sha3_256(new Uint8Array(concatenatedDataHashes));
  const eContent = assembleEContent([...aggregateHash]);
  const signature = secp256k1.sign(
    sha3_256(Uint8Array.from(eContent)),
    signer.privNative
  );
  const signatureSerialized = signature.toDERRawBytes();
  return {
    mrz,
    dataGroupConcat: Uint8Array.from(concatenatedDataHashes),
    eContent,
    encryptedDigest: signatureSerialized,
  };
}

function validateMock(mock: PassportMock, pubkey: Uint8Array) {
  // Verify the signature on econtent
  const isSignatureValid = secp256k1.verify(
    mock.encryptedDigest,
    sha3_256(mock.eContent),
    pubkey
  );
  if (!isSignatureValid) {
    throw new Error('Invalid signature');
  }

  // Verify the hash(dataGroupConcat) (len 32) is the tail of eContent
  const dataGroupConcatHash = sha3_256(mock.dataGroupConcat);
  const eContentTail = mock.eContent.slice(-32);
  if (!arrayEquals(dataGroupConcatHash, eContentTail)) {
    throw new Error(
      'Hash of dataGroupConcat does not match the tail of eContent'
    );
  }

  // Verify hash(format(mrz)) is substring of dataGroupConcat
  const formattedMrz = formatMrz(mock.mrz);
  const mrzHash = sha3_256(formattedMrz);
  const position = findSubarrayIndex(mock.dataGroupConcat, mrzHash);
  if (position === -1) {
    // console.log(position);
    // console.log(mrzHash);
    // console.log(
    //   mock.dataGroupConcat.slice(position, position + mrzHash.length)
    // );
    throw new Error('hash(format(MRZ)) is not in dataGroupConcat');
  }

  // console.log(sha3_256(mock.dataGroupConcat));
  return position;
}

interface InputO1 {
  signature: Ecdsa;
  pubkey: Secp256k1;
  mrz: string;
  dataGroupConcat: Uint8Array;
  position: number;
}

function validateMockO1Mrz(
  mrz: UInt8[],
  dataGroupConcat: UInt8[],
  position: number
) {
  // verify mrz <=> dataGroupConcat relation
  const formatted = [97, 91, 95, 31, 88].map(UInt8.from);
  for (const c of mrz) {
    formatted.push(c);
  }
  const mrzHash = Hash.SHA3_256.hash(Bytes.from(formatted)).bytes;

  assert(
    dataGroupConcat.length >= position + 32,
    'not enough data after position'
  );
  for (let i = 0; i < 32; i += 1) {
    mrzHash[i].assertEquals(
      dataGroupConcat[position + i],
      'mrzHash not at concat[position]'
    );
  }
}

function econtentFromConcatHash(concatHash: Bytes): Bytes {
  const eContent: UInt8[] = [
    49, 102, 48, 21, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 3, 49, 8, 6, 6,
    103, -127, 8, 1, 1, 1, 48, 28, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 5,
    49, 15, 23, 13, 49, 57, 49, 50, 49, 54, 49, 55, 50, 50, 51, 56, 90, 48, 47,
    6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 4, 49, 34, 4, 32,
  ].map((n) => UInt8.from(n < 0 ? n + 256 : n));
  eContent.push(...concatHash.bytes);
  return Bytes.from(eContent);
}

function signatureNoble2o1js(sig: Uint8Array): Ecdsa {
  const noble = secp256k1.Signature.fromDER(sig);
  const r = BigInt('0x' + noble.r.toString(16));
  const s = BigInt('0x' + noble.s.toString(16));

  return new Ecdsa({
    r,
    s,
  });
}

function validateMockO1Signature(
  dataGroupConcat: UInt8[],
  signature: Ecdsa,
  pubkey: Secp256k1
) {
  const concatHash = Hash.SHA3_256.hash(Bytes.from(dataGroupConcat));
  const eContent = econtentFromConcatHash(concatHash);
  const eContentHash = Hash.SHA3_256.hash(eContent);
  const aff = hashToScalar(eContentHash);
  const isValid = signature.verifySignedHashV2(aff, pubkey);
  isValid.assertTrue('signature validation failed');
}

function validateMockO1(inp: InputO1) {
  const mrzAscii = strToAscii(inp.mrz);
  const concat = Bytes.from(inp.dataGroupConcat).bytes;

  validateMockO1Mrz(mrzAscii, concat, inp.position);

  validateMockO1Signature(concat, inp.signature, inp.pubkey);
}

describe('pass test', () => {
  let signer: SignerNoble;
  let mock: PassportMock;

  beforeAll(() => {
    signer = new SignerNoble();
    mock = preparePassport(signer, MRZ_SAMPLE);
    fs.writeFileSync('mock.json', stringifyPassportMock(mock));
  });

  it('generates passport and validates normally', async () => {
    expect(validateMock(mock, signer.pubNative));
  });

  it('validates with o1js', async () => {
    const position = validateMock(mock, signer.pubNative);
    expect(position).toEqual(33);
    const inp: InputO1 = {
      signature: signatureNoble2o1js(mock.encryptedDigest),
      pubkey: signer.pubO1,
      mrz: mock.mrz,
      dataGroupConcat: mock.dataGroupConcat,
      position,
    };
    // console.log(sha3_256(formatMrz(mock.mrz)));
    // console.log(position);
    expect(validateMockO1(inp));
  });
});
