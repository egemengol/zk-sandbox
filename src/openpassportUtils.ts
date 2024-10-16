export function formatMrz(mrz: string) {
  const mrzCharcodes = [...mrz].map((char) => char.charCodeAt(0));

  mrzCharcodes.unshift(88); // the length of the mrz data
  mrzCharcodes.unshift(95, 31); // the MRZ_INFO_TAG
  mrzCharcodes.unshift(91); // the new length of the whole array
  mrzCharcodes.unshift(97); // the tag for DG1

  return mrzCharcodes;
}

export function assembleEContent(messageDigest: number[]) {
  const constructedEContent = [];

  // Detailed description is in private file r&d.ts for now
  // First, the tag and length, assumed to be always the same
  constructedEContent.push(...[49, 102]);

  // 1.2.840.113549.1.9.3 is RFC_3369_CONTENT_TYPE_OID
  constructedEContent.push(
    ...[48, 21, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 3]
  );
  // 2.23.136.1.1.1 is ldsSecurityObject
  constructedEContent.push(...[49, 8, 6, 6, 103, -127, 8, 1, 1, 1]);

  // 1.2.840.113549.1.9.5 is signing-time
  constructedEContent.push(
    ...[48, 28, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 5]
  );
  // mock time of signature
  constructedEContent.push(
    ...[49, 15, 23, 13, 49, 57, 49, 50, 49, 54, 49, 55, 50, 50, 51, 56, 90]
  );
  // 1.2.840.113549.1.9.4 is RFC_3369_MESSAGE_DIGEST_OID
  constructedEContent.push(
    ...[48, 47, 6, 9, 42, -122, 72, -122, -9, 13, 1, 9, 4]
  );
  // TAG and length of the message digest
  constructedEContent.push(...[49, 34, 4, 32]);

  constructedEContent.push(...messageDigest);
  return Uint8Array.from(constructedEContent);
}

const MOCK_AUTHORITY = (() => {
  const mock_dsc_key_sha256_ecdsa = `-----BEGIN EC PRIVATE KEY-----
  MHcCAQEEILM+tyrOADmGjsoNiF/MBuvIscs80M4i1QjVnDy/VBJkoAoGCCqGSM49
  AwEHoUQDQgAEQGjDJAD3r/b7oRH2TrgidhLtX+ThLntgul4cdoSEb1fmFcrTgXr4
  utAT4/K3aMZ3GrVtCMb5e94lwOlhuOdPdw==
  -----END EC PRIVATE KEY-----
  `;

  const mock_dsc_sha256_ecdsa = `-----BEGIN CERTIFICATE-----
  MIICBzCCAa2gAwIBAgIUepk5fECPtH8DJL55fJcGsPCHHowwCgYIKoZIzj0EAwIw
  cjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5MRUw
  EwYDVQQKDAxPcmdhbml6YXRpb24xEzARBgNVBAsMCkRlcGFydG1lbnQxGDAWBgNV
  BAMMD3d3dy5leGFtcGxlLmNvbTAeFw0yNDA4MjcxNDE3NDdaFw0yNTA4MjcxNDE3
  NDdaMHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVTdGF0ZTENMAsGA1UEBwwEQ2l0
  eTEVMBMGA1UECgwMT3JnYW5pemF0aW9uMRMwEQYDVQQLDApEZXBhcnRtZW50MRgw
  FgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
  AARAaMMkAPev9vuhEfZOuCJ2Eu1f5OEue2C6Xhx2hIRvV+YVytOBevi60BPj8rdo
  xncatW0Ixvl73iXA6WG45093oyEwHzAdBgNVHQ4EFgQUUa6p5iCBqbhslwC79LHX
  EyYTiP0wCgYIKoZIzj0EAwIDSAAwRQIhAP6XA1AWr8v6f7EJz3u5GuudyCKqiuBY
  mDhB0W8OhhR2AiAMTm++57YJkbQNxzL75nypXSdZmBfiQXSNM0NFpHEuIQ==
  -----END CERTIFICATE-----
  `;
})();

export const mock_dsc_key_sha256_ecdsa = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILM+tyrOADmGjsoNiF/MBuvIscs80M4i1QjVnDy/VBJkoAoGCCqGSM49
AwEHoUQDQgAEQGjDJAD3r/b7oRH2TrgidhLtX+ThLntgul4cdoSEb1fmFcrTgXr4
utAT4/K3aMZ3GrVtCMb5e94lwOlhuOdPdw==
-----END EC PRIVATE KEY-----
`;

export const mock_dsc_sha256_ecdsa = `-----BEGIN CERTIFICATE-----
MIICBzCCAa2gAwIBAgIUepk5fECPtH8DJL55fJcGsPCHHowwCgYIKoZIzj0EAwIw
cjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5MRUw
EwYDVQQKDAxPcmdhbml6YXRpb24xEzARBgNVBAsMCkRlcGFydG1lbnQxGDAWBgNV
BAMMD3d3dy5leGFtcGxlLmNvbTAeFw0yNDA4MjcxNDE3NDdaFw0yNTA4MjcxNDE3
NDdaMHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVTdGF0ZTENMAsGA1UEBwwEQ2l0
eTEVMBMGA1UECgwMT3JnYW5pemF0aW9uMRMwEQYDVQQLDApEZXBhcnRtZW50MRgw
FgYDVQQDDA93d3cuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARAaMMkAPev9vuhEfZOuCJ2Eu1f5OEue2C6Xhx2hIRvV+YVytOBevi60BPj8rdo
xncatW0Ixvl73iXA6WG45093oyEwHzAdBgNVHQ4EFgQUUa6p5iCBqbhslwC79LHX
EyYTiP0wCgYIKoZIzj0EAwIDSAAwRQIhAP6XA1AWr8v6f7EJz3u5GuudyCKqiuBY
mDhB0W8OhhR2AiAMTm++57YJkbQNxzL75nypXSdZmBfiQXSNM0NFpHEuIQ==
-----END CERTIFICATE-----
`;

export const sampleDataHashes_small = [
  [
    2,
    [
      -66, 82, -76, -21, -34, 33, 79, 50, -104, -120, -114, 35, 116, -32, 6,
      -14, -100, -115, -128, -8,
    ],
  ],
  [
    3,
    [
      0, -62, 104, 108, -19, -10, 97, -26, 116, -58, 69, 110, 26, 87, 17, 89,
      110, -57, 108, -6,
    ],
  ],
  [
    14,
    [
      76, 123, -40, 13, 51, -29, 72, -11, 59, -63, -18, -90, 103, 49, 23, -92,
      -85, -68, -62, -59,
    ],
  ],
] as [number, number[]][];

export const sampleDataHashes_large = [
  [
    2,
    [
      -66, 82, -76, -21, -34, 33, 79, 50, -104, -120, -114, 35, 116, -32, 6,
      -14, -100, -115, -128, -8, 10, 61, 98, 86, -8, 45, -49, -46, 90, -24, -81,
      38,
    ],
  ],
  [
    3,
    [
      0, -62, 104, 108, -19, -10, 97, -26, 116, -58, 69, 110, 26, 87, 17, 89,
      110, -57, 108, -6, 36, 21, 39, 87, 110, 102, -6, -43, -82, -125, -85, -82,
    ],
  ],
  [
    11,
    [
      -120, -101, 87, -112, 111, 15, -104, 127, 85, 25, -102, 81, 20, 58, 51,
      75, -63, 116, -22, 0, 60, 30, 29, 30, -73, -115, 72, -9, -1, -53, 100,
      124,
    ],
  ],
  [
    12,
    [
      41, -22, 106, 78, 31, 11, 114, -119, -19, 17, 92, 71, -122, 47, 62, 78,
      -67, -23, -55, -42, 53, 4, 47, -67, -55, -123, 6, 121, 34, -125, 64, -114,
    ],
  ],
  [
    13,
    [
      91, -34, -46, -63, 62, -34, 104, 82, 36, 41, -118, -3, 70, 15, -108, -48,
      -100, 45, 105, -85, -15, -61, -71, 43, -39, -94, -110, -55, -34, 89, -18,
      38,
    ],
  ],
  [
    14,
    [
      76, 123, -40, 13, 51, -29, 72, -11, 59, -63, -18, -90, 103, 49, 23, -92,
      -85, -68, -62, -59, -100, -69, -7, 28, -58, 95, 69, 15, -74, 56, 54, 38,
    ],
  ],
] as [number, number[]][];
