import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/p256';
import * as asn1 from 'asn1js';
import { Certificate } from 'pkijs';
import { sha3_256 } from '@noble/hashes/sha3';
import * as fs from 'fs';

function dsc2pubkey(dsc: string) {
  const certBuffer = Buffer.from(
    dsc.replace(/(-----(BEGIN|END) CERTIFICATE-----|\n)/g, ''),
    'base64'
  );
  const asn1Data = asn1.fromBER(certBuffer);
  const cert = new Certificate({ schema: asn1Data.result });
  const publicKeyInfo = cert.subjectPublicKeyInfo;
  const publicKeyBuffer =
    publicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
  return publicKeyBuffer;
}

function verifyEContent(
  eContent: Uint8Array,
  encryptedDigest: Uint8Array,
  publicKey: Uint8Array
) {
  const eContentHash = sha3_256(eContent);
  console.log(p256.verify(encryptedDigest, eContentHash, publicKey));
}

function main() {
  const passportDataRaw = fs.readFileSync('./passportData.json', 'utf8');
  const passportData = JSON.parse(passportDataRaw);
  const { dsc, dataGroupHashes, eContent, encryptedDigest } = passportData;

  const pubkey = dsc2pubkey(dsc);
  console.log(pubkey);
  verifyEContent(
    Uint8Array.from(eContent),
    Uint8Array.from(encryptedDigest),
    pubkey
  );
}
main();
