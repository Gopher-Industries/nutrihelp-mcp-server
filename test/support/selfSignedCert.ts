/**
 * Throwaway self-signed certificate from `node:crypto`. A fixture so `https.createServer` can
 * bind; nothing verifies it. Avoids PATH `openssl` (skip would look like a pass) and avoids a
 * committed PEM (secret-shaped). Key is generated per call and discarded with the temp directory.
 */

import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';

export interface SelfSignedCertificate {
  /** Private key, PKCS#8 PEM. What the issuer reads as its TLS key. */
  readonly keyPem: string;
  /** The certificate, PEM. */
  readonly certPem: string;
}

const DER_INTEGER = 0x02;
const DER_BIT_STRING = 0x03;
const DER_OID = 0x06;
const DER_UTF8_STRING = 0x0c;
const DER_UTC_TIME = 0x17;
const DER_SEQUENCE = 0x30;
const DER_SET = 0x31;
/** Context tag [0], constructed: the explicit wrapper the version field sits in. */
const DER_CONTEXT_0 = 0xa0;

const DER_NULL = Buffer.from([0x05, 0x00]);

/** sha256WithRSAEncryption, 1.2.840.113549.1.1.11. */
const OID_SHA256_WITH_RSA = Buffer.from([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]);

/** id-at-commonName, 2.5.4.3. */
const OID_COMMON_NAME = Buffer.from([0x55, 0x04, 0x03]);

/** X.509 v3. The value is one less than the version number, so v3 is 2. */
const X509_VERSION_3 = 2;

const ONE_HOUR_MS = 3_600_000;
const ONE_DAY_MS = 86_400_000;

/** Short form below 128, long form above it. Anything else is not a length OpenSSL will read. */
function derLength(size: number): Buffer {
  if (size < 0x80) return Buffer.from([size]);
  const bytes: number[] = [];
  for (let remaining = size; remaining > 0; remaining = Math.floor(remaining / 256)) {
    bytes.unshift(remaining % 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, ...body: readonly Buffer[]): Buffer {
  const content = Buffer.concat(body);
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

/** Positive INTEGER with no leading zero. A high first byte plus a 0x00 prefix is illegal padding. */
function serialNumber(): Buffer {
  const bytes = randomBytes(8);
  bytes[0] = ((bytes[0] ?? 0) % 0x7f) + 1;
  return bytes;
}

/** UTCTime is two-digit year through seconds, always Z. */
function utcTime(at: Date): Buffer {
  return der(DER_UTC_TIME, Buffer.from(`${at.toISOString().replace(/[-:T]/g, '').slice(2, 14)}Z`));
}

/** An RDNSequence carrying one commonName, which is all a local fixture needs. */
function distinguishedName(commonName: string): Buffer {
  return der(
    DER_SEQUENCE,
    der(
      DER_SET,
      der(
        DER_SEQUENCE,
        der(DER_OID, OID_COMMON_NAME),
        der(DER_UTF8_STRING, Buffer.from(commonName, 'utf8'))
      )
    )
  );
}

function toPem(label: string, body: Buffer): string {
  const wrapped = body.toString('base64').match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${wrapped.join('\n')}\n-----END ${label}-----\n`;
}

/** Generate an RSA key and a certificate over it, valid from an hour ago for a day. */
export function selfSignedCertificate(commonName: string): SelfSignedCertificate {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const algorithm = der(DER_SEQUENCE, der(DER_OID, OID_SHA256_WITH_RSA), DER_NULL);
  const now = Date.now();

  // `spki` DER is a SubjectPublicKeyInfo already, so it goes into the TBS unwrapped.
  const tbsCertificate = der(
    DER_SEQUENCE,
    der(DER_CONTEXT_0, der(DER_INTEGER, Buffer.from([X509_VERSION_3]))),
    der(DER_INTEGER, serialNumber()),
    algorithm,
    distinguishedName(commonName),
    der(DER_SEQUENCE, utcTime(new Date(now - ONE_HOUR_MS)), utcTime(new Date(now + ONE_DAY_MS))),
    distinguishedName(commonName),
    publicKey.export({ type: 'spki', format: 'der' })
  );

  // A BIT STRING's first content byte is the count of unused trailing bits: none here.
  const certificate = der(
    DER_SEQUENCE,
    tbsCertificate,
    algorithm,
    der(
      DER_BIT_STRING,
      Buffer.concat([Buffer.from([0x00]), sign('sha256', tbsCertificate, privateKey)])
    )
  );

  return {
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    certPem: toPem('CERTIFICATE', certificate),
  };
}
