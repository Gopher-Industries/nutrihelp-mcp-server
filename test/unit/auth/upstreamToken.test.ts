/**
 * `private_key_jwt` client assertion. Verified with the matching public key (decode alone
 * proves nothing about possession). Algorithm pinned per key type, never negotiated.
 */

import { createSecretKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { decodeProtectedHeader, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import {
  CLIENT_ASSERTION_LIFETIME_SECONDS,
  CLIENT_ASSERTION_TYPE,
  clientAssertion,
} from '../../../src/auth/upstreamToken.ts';
import { AUTH_SERVER_ORIGIN, CLIENT_ID, INTROSPECTION_PATH } from '../../support/testEnv.ts';

interface KeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

const INTROSPECTION_URL = `${AUTH_SERVER_ORIGIN}${INTROSPECTION_PATH}`;

/** Pinned so the assertion's own lifetime is checkable without waiting on a clock. */
const FIXED_NOW_MS = 1_800_000_000_000;
const FIXED_NOW = new Date(FIXED_NOW_MS);

/** Keys are generated per run, never committed: a PEM in a fixture is a secret-shaped fixture. */
let ec: KeyPair;
let rsa: KeyPair;
let ed25519: KeyPair;
let otherEc: KeyPair;

beforeAll(() => {
  ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  otherEc = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  rsa = generateKeyPairSync('rsa', { modulusLength: 2048 });
  ed25519 = generateKeyPairSync('ed25519');
});

describe('the client assertion is a signature, not a decodable claim set', () => {
  it('verifies against the matching public key and names the client as both issuer and subject', async () => {
    const assertion = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });

    const { payload } = await jwtVerify(assertion, ec.publicKey, {
      issuer: CLIENT_ID,
      audience: INTROSPECTION_URL,
      currentDate: FIXED_NOW,
    });

    expect(payload.iss, 'the client is the issuer of its own assertion').toBe(CLIENT_ID);
    expect(
      payload.sub,
      'and its subject, which the specification requires — not a copy-paste of iss'
    ).toBe(CLIENT_ID);
    expect(payload.aud, 'only the endpoint being called may accept it').toBe(INTROSPECTION_URL);
  });

  it('does not verify against a different key of the same type', async () => {
    const assertion = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });

    await expect(
      jwtVerify(assertion, otherEc.publicKey, { currentDate: FIXED_NOW }),
      'a verification that passes under any key proves nothing about possession'
    ).rejects.toThrow();
  });

  it('carries no user identity — only the client, the audience and the replay fields', async () => {
    const assertion = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: 'assertion-jti-1',
    });

    const { payload } = await jwtVerify(assertion, ec.publicKey, { currentDate: FIXED_NOW });

    expect(
      Object.keys(payload).sort(),
      'the assertion mints nothing on its own: a user claim here would make it more than proof of possession'
    ).toEqual(['aud', 'exp', 'iat', 'iss', 'jti', 'sub']);
  });
});

describe('the assertion window', () => {
  it('expires exactly the declared lifetime after the injected clock', async () => {
    const assertion = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });

    const { payload } = await jwtVerify(assertion, ec.publicKey, { currentDate: FIXED_NOW });
    const iat = payload.iat ?? Number.NaN;
    const exp = payload.exp ?? Number.NaN;

    expect(iat, 'the injected clock is what iat is taken from').toBe(
      Math.floor(FIXED_NOW_MS / 1000)
    );
    expect(exp - iat, 'the window is the declared constant, not a hand-written number').toBe(
      CLIENT_ASSERTION_LIFETIME_SECONDS
    );
    expect(
      CLIENT_ASSERTION_LIFETIME_SECONDS,
      'short enough that a captured assertion is replayable only briefly'
    ).toBeLessThanOrEqual(300);
    expect(
      CLIENT_ASSERTION_LIFETIME_SECONDS,
      'long enough to survive clock skew against the authorization server'
    ).toBeGreaterThan(0);
  });

  it('takes the real clock when no instant is injected', async () => {
    const before = Math.floor(Date.now() / 1000);
    const assertion = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: undefined,
      jti: undefined,
    });
    const after = Math.floor(Date.now() / 1000);

    const { payload } = await jwtVerify(assertion, ec.publicKey);
    const iat = payload.iat ?? Number.NaN;

    expect(
      iat,
      'an injected clock is a test affordance, not the production path'
    ).toBeGreaterThanOrEqual(before);
    expect(iat).toBeLessThanOrEqual(after);
  });

  it('mints a fresh jti per call, and round-trips an injected one', async () => {
    const first = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });
    const second = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });

    const firstJti = (await jwtVerify(first, ec.publicKey, { currentDate: FIXED_NOW })).payload.jti;
    const secondJti = (await jwtVerify(second, ec.publicKey, { currentDate: FIXED_NOW })).payload
      .jti;

    expect(firstJti, 'a jti must be present for the endpoint to detect replay').toBeDefined();
    expect(
      secondJti,
      'two assertions from the same clock must still differ: a fixed jti would make every assertion in a second identical'
    ).not.toBe(firstJti);

    const pinned = await clientAssertion({
      key: ec.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: 'pinned-jti',
    });
    expect((await jwtVerify(pinned, ec.publicKey, { currentDate: FIXED_NOW })).payload.jti).toBe(
      'pinned-jti'
    );
  });
});

describe('the signing algorithm is pinned by key type, never selected by the key', () => {
  it.each([
    ['ec', 'ES256'],
    ['rsa', 'RS256'],
    ['ed25519', 'EdDSA'],
  ] as const)('signs an %s key with %s and nothing else', async (keyType, expectedAlg) => {
    const pairs: Readonly<Record<string, KeyPair>> = {
      ec,
      rsa,
      ed25519,
    };
    const pair = pairs[keyType];
    if (pair === undefined) throw new Error(`no generated key pair for ${keyType}`);

    const assertion = await clientAssertion({
      key: pair.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });

    expect(decodeProtectedHeader(assertion).alg, `${keyType} must sign as ${expectedAlg}`).toBe(
      expectedAlg
    );
    expect(decodeProtectedHeader(assertion).typ).toBe('JWT');

    // The header is a claim about the signature; verifying under the pinned algorithm only is
    // what makes it a fact.
    const { payload } = await jwtVerify(assertion, pair.publicKey, {
      algorithms: [expectedAlg],
      currentDate: FIXED_NOW,
    });
    expect(payload.iss).toBe(CLIENT_ID);
  });

  /**
   * `rsa-pss` is absent from the table on purpose, and that absence is asserted here.
   * Node reports the type then fails at sign with `Invalid key type` if PS256 is forced
   * (measured, Node v24.19.0). Left absent, it falls through to "no pinned algorithm: refuse".
   */
  it('refuses an rsa-pss key, which is why the table has no row for it', async () => {
    const rsaPss = generateKeyPairSync('rsa-pss', { modulusLength: 2048 });

    expect(rsaPss.privateKey.asymmetricKeyType, 'the key type a row would have had to name').toBe(
      'rsa-pss'
    );

    const attempt = clientAssertion({
      key: rsaPss.privateKey,
      clientId: CLIENT_ID,
      audience: INTROSPECTION_URL,
      now: FIXED_NOW,
      jti: undefined,
    });

    await expect(attempt).rejects.toThrow(TypeError);
    await expect(
      attempt,
      'refused for the absent key type, before signing — not by the signer failing on the key'
    ).rejects.toThrow(/rsa-pss/);
  });

  it('refuses a key type it has no pinned algorithm for, rather than guessing', async () => {
    const x25519 = generateKeyPairSync('x25519');

    await expect(
      clientAssertion({
        key: x25519.privateKey,
        clientId: CLIENT_ID,
        audience: INTROSPECTION_URL,
        now: FIXED_NOW,
        jti: undefined,
      })
    ).rejects.toThrow(TypeError);
  });

  it('refuses a symmetric secret: this server proves possession, it does not share one', async () => {
    const secret = createSecretKey(Buffer.from('a'.repeat(32), 'utf8'));

    await expect(
      clientAssertion({
        key: secret,
        clientId: CLIENT_ID,
        audience: INTROSPECTION_URL,
        now: FIXED_NOW,
        jti: undefined,
      }),
      'a symmetric key would mean the authorization server holds the same secret'
    ).rejects.toThrow(TypeError);
  });
});

describe('the client identifier and audience are required, never derived', () => {
  it.each(['', ' ', '\t\n'])('refuses a blank client identifier (%j)', async (clientId) => {
    await expect(
      clientAssertion({
        key: ec.privateKey,
        clientId,
        audience: INTROSPECTION_URL,
        now: FIXED_NOW,
        jti: undefined,
      }),
      'blank is the shape an invented default arrives in — the resource identifier is not a stand-in'
    ).rejects.toThrow(TypeError);
  });

  it.each(['', '   '])('refuses a blank audience (%j)', async (audience) => {
    await expect(
      clientAssertion({
        key: ec.privateKey,
        clientId: CLIENT_ID,
        audience,
        now: FIXED_NOW,
        jti: undefined,
      }),
      'an assertion no endpoint is named in is one every endpoint could accept'
    ).rejects.toThrow(TypeError);
  });
});

describe('the constants the endpoint reads', () => {
  it('pins the RFC 7521 client-assertion type literally', () => {
    expect(
      CLIENT_ASSERTION_TYPE,
      'the endpoint matches this string exactly; a paraphrase is a rejected request'
    ).toBe('urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  });
});
