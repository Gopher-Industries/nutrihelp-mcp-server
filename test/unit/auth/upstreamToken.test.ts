/**
 * `private_key_jwt` client assertion, the RFC 8693 exchange built on it, and the credential
 * cache in front of that. Assertions are verified with the matching public key (decode alone
 * proves nothing about possession) and the algorithm is pinned per key type, never negotiated.
 *
 * The exchange cases drive the real `src/upstream/client.ts` over a mocked transport, so the
 * form body, the header allowlist and the required deadline are exercised rather than described.
 */

import { createSecretKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { decodeProtectedHeader, jwtVerify, type JWTPayload } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CLIENT_ASSERTION_LIFETIME_SECONDS,
  CLIENT_ASSERTION_TYPE,
  MAX_CACHED_CREDENTIALS,
  SUBJECT_TOKEN_TYPE,
  clientAssertion,
  createUpstreamCredentialProvider,
  exchangeUpstreamCredential,
  subjectTokenDigest,
  type ExchangeOperationalEvent,
  type ExchangeOptions,
  type ExchangeSecurityEvent,
  type UpstreamCredentialRequest,
} from '../../../src/auth/upstreamToken.ts';
import type { ActiveGrant } from '../../../src/auth/revocation.ts';
import { McpError, type McpErrorClass } from '../../../src/errors.ts';
import { forgeActiveGrant } from '../../support/activeGrant.ts';
import {
  installUpstreamMock,
  type UpstreamMock,
  type WireCall,
} from '../../support/upstreamMock.ts';
import {
  AUTH_SERVER_ORIGIN,
  CLIENT_ID,
  GRANT_A,
  INTROSPECTION_PATH,
  MCP_CLIENT_ID,
  TOKEN_EXCHANGE_PATH,
  USER_A,
} from '../../support/testEnv.ts';

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

/* ---------------------------------------------------------------------------------------------
 * RFC 8693 exchange and the credential cache
 *
 * The transport beneath `src/upstream/client.ts` is mocked; the client itself never is, so the
 * deny-list, the header allowlist and the required deadline are all exercised for real.
 * ------------------------------------------------------------------------------------------- */

const TOKEN_EXCHANGE_URL = `${AUTH_SERVER_ORIGIN}${TOKEN_EXCHANGE_PATH}`;
const CORRELATION_ID = 'correlation-under-test';
const DEADLINE_MS = 5_000;

/** Distinctive enough that a substring search over a wire transcript cannot match by accident. */
const SUBJECT_TOKEN = 'subject-token-value-9f3a1c';
const CREDENTIAL = 'exchanged-credential-7c1d40';

/** Arbitrary fixed instant. Every clock here is injected, so nothing waits. */
const START_MS = 1_800_000_000_000;

/** What the module will reuse a credential for, once the safety margin is taken off. */
const USABLE_WINDOW_MS = 120_000 - 10_000;

let upstream: UpstreamMock;
let clockMs: number;

interface ExchangeHarness {
  readonly options: ExchangeOptions;
  readonly operational: ExchangeOperationalEvent[];
  readonly security: ExchangeSecurityEvent[];
}

interface OptionOverrides {
  readonly tokenEndpointUrl?: string;
  readonly clientId?: string;
  readonly clientAssertionKey?: KeyObject;
}

function harness(overrides: OptionOverrides = {}): ExchangeHarness {
  const operational: ExchangeOperationalEvent[] = [];
  const security: ExchangeSecurityEvent[] = [];

  return {
    operational,
    security,
    options: {
      tokenEndpointUrl: overrides.tokenEndpointUrl ?? TOKEN_EXCHANGE_URL,
      clientId: overrides.clientId ?? MCP_CLIENT_ID,
      clientAssertionKey: overrides.clientAssertionKey ?? ec.privateKey,
      now: () => clockMs,
      logOperational: (event) => operational.push(event),
      logSecurity: (event) => security.push(event),
    },
  };
}

interface RequestOverrides {
  readonly subjectToken?: string;
  readonly grant?: ActiveGrant;
  readonly deadlineMs?: number;
}

function exchangeRequest(overrides: RequestOverrides = {}): UpstreamCredentialRequest {
  const subjectToken = overrides.subjectToken ?? SUBJECT_TOKEN;
  return {
    subjectToken,
    // Bound to THIS token by default. A case that wants a mispaired grant has to say so, which
    // is the right way round: the hazard should be the thing you have to write out.
    grant: overrides.grant ?? forgeActiveGrant({ subjectToken }),
    correlationId: CORRELATION_ID,
    deadlineMs: overrides.deadlineMs ?? DEADLINE_MS,
  };
}

/** A successful RFC 8693 reply. Fields are spelled out per case rather than deleted from a base. */
function credentialPayload(expiresIn: number): Record<string, unknown> {
  return {
    access_token: CREDENTIAL,
    issued_token_type: SUBJECT_TOKEN_TYPE,
    token_type: 'Bearer',
    expires_in: expiresIn,
  };
}

/** One reply, consumed once, so a sequence of cases can register different answers in order. */
function replyOnce(status: number, body: object | string, delayMs?: number): void {
  upstream.route({
    origin: AUTH_SERVER_ORIGIN,
    path: TOKEN_EXCHANGE_PATH,
    method: 'POST',
    status,
    body,
    once: true,
    ...(delayMs === undefined ? {} : { delayMs }),
  });
}

function exchangeCalls(): WireCall[] {
  return upstream.callsTo(TOKEN_EXCHANGE_PATH);
}

/** The form fields of the nth exchange on the wire, parsed from the real request body. */
function formOf(index: number): URLSearchParams {
  const call = exchangeCalls()[index];
  expect(call, `expected an exchange request at index ${String(index)}`).toBeDefined();
  return new URLSearchParams(call?.body ?? '');
}

/** The assertion's verified claims. Decoding alone would prove nothing about the signature. */
async function assertionClaimsOf(index: number): Promise<JWTPayload> {
  const assertion = formOf(index).get('client_assertion') ?? '';
  const { payload } = await jwtVerify(assertion, ec.publicKey, { currentDate: new Date(clockMs) });
  return payload;
}

/** Rejects with an `McpError` of exactly this class. "Did not resolve" is not enough. */
async function expectRejectedClass(
  promise: Promise<unknown>,
  expected: McpErrorClass,
  context: string
): Promise<McpError> {
  let caught: unknown;
  await promise.then(
    () => undefined,
    (error: unknown) => {
      caught = error;
    }
  );

  expect(caught, `${context}: expected a rejection, got a resolved value`).toBeInstanceOf(McpError);
  const error = caught as McpError;
  expect(error.class, `${context}: wrong taxonomy class`).toBe(expected);
  return error;
}

/** The log-side error code of an upstream failure. */
function errorCodeOf(error: McpError): string {
  const payload = error.toLog();
  return payload.class === 'upstream_failure' ? payload.errorCode : `(class ${payload.class})`;
}

describe('the RFC 8693 token exchange', () => {
  beforeEach(() => {
    clockMs = START_MS;
    upstream = installUpstreamMock([]);
  });

  afterEach(async () => {
    await upstream.restore();
  });

  describe('the request it puts on the wire', () => {
    it('sends exactly five form parameters, and every omission is a decision', async () => {
      replyOnce(200, credentialPayload(120));

      await exchangeUpstreamCredential(harness().options, exchangeRequest());

      const form = formOf(0);
      expect(
        [...form.keys()].sort(),
        'scope, requested_token_type, resource and audience are all absent on purpose: the issuer refuses any resource or audience that is not the backend API audience it configures, and that string is not knowable from this repository'
      ).toEqual([
        'client_assertion',
        'client_assertion_type',
        'grant_type',
        'subject_token',
        'subject_token_type',
      ]);

      expect(form.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
      expect(form.get('subject_token_type')).toBe('urn:ietf:params:oauth:token-type:access_token');
      expect(
        form.get('client_assertion_type'),
        'the already-exported constant, not a second spelling of it'
      ).toBe(CLIENT_ASSERTION_TYPE);
    });

    it('presents the inbound token verbatim, as the subject token and under no other name', async () => {
      replyOnce(200, credentialPayload(120));

      await exchangeUpstreamCredential(harness().options, exchangeRequest());

      const form = formOf(0);
      expect(form.get('subject_token'), 'verbatim: a re-encoded token is a different token').toBe(
        SUBJECT_TOKEN
      );
      expect(
        [...form.entries()].filter(([, value]) => value.includes(SUBJECT_TOKEN)),
        'exactly one field carries it'
      ).toHaveLength(1);
    });

    it('sends no Authorization header: this endpoint authenticates from the body', async () => {
      replyOnce(200, credentialPayload(120));

      await exchangeUpstreamCredential(harness().options, exchangeRequest());

      const headers = exchangeCalls()[0]?.headers ?? {};
      const names = Object.keys(headers).map((name) => name.toLowerCase());
      expect(names, 'private_key_jwt lives in the form body, never in a header').not.toContain(
        'authorization'
      );
      expect(names, 'nor a cookie, which would be an ambient credential').not.toContain('cookie');
    });

    it('names the token endpoint as the assertion audience, never the introspection URL', async () => {
      replyOnce(200, credentialPayload(120));

      await exchangeUpstreamCredential(harness().options, exchangeRequest());

      const claims = await assertionClaimsOf(0);
      expect(
        claims.aud,
        'the authorization server accepts an assertion only at the endpoint it names'
      ).toBe(TOKEN_EXCHANGE_URL);
      expect(
        claims.aud,
        'and the two endpoints are not interchangeable: an assertion minted for introspection is refused here, which is the whole reason the composition root derives two URLs rather than reusing one'
      ).not.toBe(INTROSPECTION_URL);
      expect(TOKEN_EXCHANGE_URL, 'control: the two URLs really do differ').not.toBe(
        INTROSPECTION_URL
      );
      expect(claims.iss, 'the client authenticates as itself').toBe(MCP_CLIENT_ID);
      expect(claims.sub).toBe(MCP_CLIENT_ID);
    });

    it('mints a fresh jti per exchange, including one made after a cache eviction', async () => {
      replyOnce(200, credentialPayload(120));
      replyOnce(200, credentialPayload(120));

      const provider = createUpstreamCredentialProvider(harness().options);
      await provider.credentialFor(exchangeRequest());
      // Read before the clock moves: each assertion is only verifiable inside its own window,
      // and an expired-assertion failure here would look like a jti finding.
      const first = await assertionClaimsOf(0);

      // Past the usable window, so the second call is a real exchange rather than a cache hit.
      clockMs = START_MS + USABLE_WINDOW_MS + 1;
      await provider.credentialFor(exchangeRequest());

      expect(
        exchangeCalls(),
        'the eviction must actually have produced a second exchange'
      ).toHaveLength(2);

      const second = await assertionClaimsOf(1);
      expect(first.jti, 'a jti must be present for the endpoint to detect replay').toBeDefined();
      expect(
        second.jti,
        'a cache eviction must not replay the assertion the evicted entry was fetched with'
      ).not.toBe(first.jti);
    });

    it('calls the exact path, with no trailing slash for a redirect to correct', async () => {
      replyOnce(200, credentialPayload(120));

      await exchangeUpstreamCredential(harness().options, exchangeRequest());

      expect(
        exchangeCalls()[0]?.path,
        'the endpoint publishes no trailing-slash redirect, and its rate-limit carve-out matches the path by exact equality, so a near-miss lands in the global bucket'
      ).toBe(TOKEN_EXCHANGE_PATH);
      expect(exchangeCalls()[0]?.method).toBe('POST');
    });
  });

  describe('the endpoint URL and the request budget are guarded here, not assumed', () => {
    it.each([
      ['http', `http://auth.nutrihelp.test${TOKEN_EXCHANGE_PATH}`],
      ['not a URL at all', 'api/oauth/token'],
    ])('refuses a %s token endpoint when the provider is built', (_label, url) => {
      expect(
        () => createUpstreamCredentialProvider(harness({ tokenEndpointUrl: url }).options),
        'the subject token travels in this request body, so the scheme is a credential-exposure decision'
      ).toThrow(TypeError);
    });

    it('refuses the same URL on a direct exchange, not only through the provider', async () => {
      const url = `http://auth.nutrihelp.test${TOKEN_EXCHANGE_PATH}`;
      await expect(
        exchangeUpstreamCredential(harness({ tokenEndpointUrl: url }).options, exchangeRequest())
      ).rejects.toThrow(TypeError);
      expect(exchangeCalls(), 'and nothing reached the wire').toHaveLength(0);
    });

    it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
      'refuses the unusable deadline %p rather than computing a replacement',
      async (deadlineMs) => {
        const { options, operational } = harness();

        const error = await expectRejectedClass(
          exchangeUpstreamCredential(options, exchangeRequest({ deadlineMs })),
          'upstream_failure',
          `deadline ${String(deadlineMs)}`
        );

        expect(
          errorCodeOf(error),
          'an egress-door refusal is its own code: unlike a timeout it never clears on retry'
        ).toBe('exchange_request_unbuildable');
        expect(operational.at(-1)?.statusClass).toBe('unusable_request');
        expect(exchangeCalls(), 'nothing may reach the wire unbounded').toHaveLength(0);
      }
    );
  });

  describe('the response is read rather than assumed', () => {
    it.each([
      ['no access_token', { token_type: 'Bearer', expires_in: 120 }],
      ['an empty access_token', { access_token: '', token_type: 'Bearer', expires_in: 120 }],
      ['a non-string access_token', { access_token: 42, expires_in: 120 }],
      ['no expires_in', { access_token: CREDENTIAL, token_type: 'Bearer' }],
      ['a string expires_in', { access_token: CREDENTIAL, expires_in: '120' }],
      ['a zero expires_in', { access_token: CREDENTIAL, expires_in: 0 }],
      ['a negative expires_in', { access_token: CREDENTIAL, expires_in: -30 }],
      [
        'a token_type that is not Bearer',
        { access_token: CREDENTIAL, expires_in: 120, token_type: 'mac' },
      ],
      ['an array instead of an object', [{ access_token: CREDENTIAL, expires_in: 120 }]],
    ])('refuses a 200 carrying %s', async (_label, body) => {
      replyOnce(200, body);
      const { options, operational } = harness();

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        'malformed exchange response'
      );

      expect(errorCodeOf(error)).toBe('exchange_malformed');
      expect(
        operational.at(-1)?.endpointClass,
        'the endpoint CLASS, never the path: a path in a log payload is still a path'
      ).toBe('authorization_server_token_exchange');
    });

    it('refuses a 200 that hands back the subject token as the credential', async () => {
      replyOnce(200, {
        access_token: SUBJECT_TOKEN,
        token_type: 'Bearer',
        expires_in: 120,
      });
      const { options, security } = harness();

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        'issuer echoed the subject token'
      );

      expect(
        errorCodeOf(error),
        'a 2xx is not consent to hold whatever came back. An echoed subject token accepted here is the inbound token attached to a data-backend request by the first caller that uses it'
      ).toBe('exchange_echoed_subject_token');
      expect(security.map((event) => event.event)).toEqual(['token_exchange_echoed_subject_token']);
    });

    it('still accepts a credential that merely CONTAINS the subject token as a substring', async () => {
      replyOnce(200, {
        access_token: `${SUBJECT_TOKEN}-exchanged`,
        token_type: 'Bearer',
        expires_in: 120,
      });

      const credential = await exchangeUpstreamCredential(harness().options, exchangeRequest());

      expect(
        credential.accessToken,
        'the refusal above is equality, not containment: a substring rule would reject legitimate credentials for a property that is not the hazard'
      ).toBe(`${SUBJECT_TOKEN}-exchanged`);
    });

    it('refuses a 200 whose body is not JSON at all', async () => {
      replyOnce(200, 'not json');

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(harness().options, exchangeRequest()),
        'upstream_failure',
        'unparseable exchange response'
      );
      expect(errorCodeOf(error)).toBe('exchange_malformed');
    });

    it('accepts a reply with no token_type, which is the one absence it tolerates', async () => {
      replyOnce(200, { access_token: CREDENTIAL, expires_in: 60 });

      const credential = await exchangeUpstreamCredential(harness().options, exchangeRequest());

      expect(
        credential.accessToken,
        'this server never puts token_type on the wire, so requiring it would refuse a working exchange over a value that changes no behaviour'
      ).toBe(CREDENTIAL);
    });

    it.each([
      ['caps a longer issuer lifetime at two minutes', 3600, 120],
      ['takes the issuer lifetime when it is shorter', 45, 45],
      ['accepts exactly the ceiling', 120, 120],
    ])('%s', async (_label, expiresIn, effectiveSeconds) => {
      replyOnce(200, credentialPayload(expiresIn));

      const credential = await exchangeUpstreamCredential(harness().options, exchangeRequest());

      expect(
        credential.usableUntilMs,
        'the window is measured from when the request STARTED, with the safety margin already taken off'
      ).toBe(START_MS + effectiveSeconds * 1000 - 10_000);
      expect(credential.grantId, 'the credential records the grant it was minted under').toBe(
        GRANT_A
      );
    });
  });

  describe('every refusal is the retryable class, and none of them is a 401', () => {
    it.each([
      ['400 invalid_grant', 400, { error: 'invalid_grant' }, 'exchange_subject_token_rejected'],
      [
        '401 invalid_client',
        401,
        { error: 'invalid_client' },
        'exchange_client_credential_rejected',
      ],
      ['401 with no readable body', 401, 'nope', 'exchange_client_credential_rejected'],
      [
        '401 that names invalid_grant',
        401,
        { error: 'invalid_grant' },
        'exchange_subject_token_rejected',
      ],
      ['400 invalid_request', 400, { error: 'invalid_request' }, 'exchange_status'],
      ['400 whose body is JSON but not an object', 400, '"invalid_grant"', 'exchange_status'],
      ['400 whose error code is not a string', 400, { error: 42 }, 'exchange_status'],
      ['403 access_denied', 403, { error: 'access_denied' }, 'exchange_status'],
      ['500 server_error', 500, { error: 'server_error' }, 'exchange_status'],
      ['503 with an empty body', 503, '', 'exchange_status'],
    ])('maps %s to upstream_failure', async (_label, status, body, expectedCode) => {
      replyOnce(status, body);
      const { options, operational } = harness();

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        `exchange refused with ${String(status)}`
      );

      expect(
        errorCodeOf(error),
        'an exchange refusal is never presented as an expired inbound token: a 401 here would send every client into its refresh-and-retry path over a failure no refresh fixes'
      ).toBe(expectedCode);
      expect(operational.at(-1)?.event).toBe('token_exchange_failed');
      expect(error.toModel(), 'and the model is told nothing but "retryable"').toEqual({
        class: 'upstream_failure',
        message: 'The service is temporarily unavailable. The request can be retried.',
        retryable: true,
      });
    });

    it('records our own credential being refused on the security channel', async () => {
      replyOnce(401, { error: 'invalid_client' });
      const { options, security } = harness();

      await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        'invalid_client'
      );

      expect(
        security,
        'this one is ours: the key, the client id or the assertion audience is wrong, and no user action reaches it'
      ).toEqual([
        {
          event: 'token_exchange_client_credential_rejected',
          correlationId: CORRELATION_ID,
          grantId: GRANT_A,
        },
      ]);
    });

    it('reads a coded 401 by its code, not by its status', async () => {
      replyOnce(401, { error: 'invalid_grant' });
      const { options, security } = harness();

      await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        '401 invalid_grant'
      );

      expect(
        security.map((event) => event.event),
        'a stated code always wins. Reading the status first files a revocation race against our own credential: right taxonomy class, wrong security record, and an operator sent to look at a key that is fine'
      ).toEqual(['token_exchange_subject_token_rejected']);
    });

    it('records a grant that went inactive between the live check and the exchange', async () => {
      replyOnce(400, { error: 'invalid_grant' });
      const { options, security, operational } = harness();

      await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        'invalid_grant'
      );

      expect(security.map((event) => event.event)).toEqual([
        'token_exchange_subject_token_rejected',
      ]);
      expect(
        operational,
        'both channels, because a revocation race is an anomaly AND an upstream failure'
      ).toHaveLength(1);
    });

    it('does not let an invalid_grant become a cached refusal anywhere', async () => {
      replyOnce(400, { error: 'invalid_grant' });
      replyOnce(200, credentialPayload(120));

      const provider = createUpstreamCredentialProvider(harness().options);
      await expectRejectedClass(
        provider.credentialFor(exchangeRequest()),
        'upstream_failure',
        'first attempt'
      );

      const credential = await provider.credentialFor(exchangeRequest());

      expect(
        credential.accessToken,
        'this module reads one endpoint answer about a grant; the authoritative question belongs to the live check, and writing a refusal into its negative cache from here would answer a different question than the one asked'
      ).toBe(CREDENTIAL);
      expect(exchangeCalls()).toHaveLength(2);
    });

    it('classifies a spent budget as a timeout rather than as an unreachable endpoint', async () => {
      replyOnce(200, credentialPayload(120), 300);
      const { options, operational } = harness();

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest({ deadlineMs: 20 })),
        'upstream_failure',
        'spent deadline'
      );

      expect(errorCodeOf(error)).toBe('exchange_timeout');
      expect(operational.at(-1)?.statusClass).toBe('timeout');
    });

    it('classifies an endpoint that never answers as unreachable', async () => {
      // No route registered: `disableNetConnect()` refuses it the way a DNS failure would.
      const { options, operational } = harness();

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        'no endpoint'
      );

      expect(errorCodeOf(error)).toBe('exchange_unreachable');
      expect(operational.at(-1)?.statusClass).toBe('unreachable');
    });

    it('converts an unbuildable client assertion rather than letting a TypeError escape', async () => {
      const { options, operational } = harness({ clientId: '   ' });

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(options, exchangeRequest()),
        'upstream_failure',
        'blank client id'
      );

      expect(errorCodeOf(error)).toBe('exchange_assertion_unbuildable');
      expect(operational.at(-1)?.statusClass).toBe('unusable_credential');
      expect(exchangeCalls(), 'and nothing reached the wire').toHaveLength(0);
    });
  });

  describe('the credential cache', () => {
    it('serves a second request for the same token from memory', async () => {
      replyOnce(200, credentialPayload(120));
      const provider = createUpstreamCredentialProvider(harness().options);

      const first = await provider.credentialFor(exchangeRequest());
      clockMs = START_MS + 1_000;
      const second = await provider.credentialFor(exchangeRequest());

      expect(exchangeCalls(), 'one exchange, two requests').toHaveLength(1);
      expect(second).toEqual(first);
    });

    it('stops serving an entry once its window closes, margin included', async () => {
      replyOnce(200, credentialPayload(120));
      replyOnce(200, credentialPayload(120));
      const provider = createUpstreamCredentialProvider(harness().options);

      await provider.credentialFor(exchangeRequest());

      clockMs = START_MS + USABLE_WINDOW_MS - 1;
      await provider.credentialFor(exchangeRequest());
      expect(exchangeCalls(), 'one millisecond inside the window is still a hit').toHaveLength(1);

      clockMs = START_MS + USABLE_WINDOW_MS;
      await provider.credentialFor(exchangeRequest());
      expect(
        exchangeCalls(),
        'the boundary itself is a miss: the margin exists so a credential is never handed out with nothing left in it'
      ).toHaveLength(2);
    });

    it('hands back a credential too short-lived to cache, and does not cache it', async () => {
      replyOnce(200, credentialPayload(5));
      replyOnce(200, credentialPayload(5));
      const provider = createUpstreamCredentialProvider(harness().options);

      const credential = await provider.credentialFor(exchangeRequest());

      expect(
        credential.accessToken,
        'the exchange succeeded, so the caller gets what it asked for: the margin governs REUSE, not whether this request may proceed'
      ).toBe(CREDENTIAL);
      expect(
        credential.usableUntilMs,
        'a five-second credential has nothing left once the margin is taken off'
      ).toBeLessThanOrEqual(START_MS);

      await provider.credentialFor(exchangeRequest());
      expect(
        exchangeCalls(),
        'and storing it would put an entry in the map that every later read has to step over'
      ).toHaveLength(2);
    });

    it('never serves one token credential for another', async () => {
      replyOnce(200, credentialPayload(120));
      replyOnce(200, credentialPayload(120));
      const provider = createUpstreamCredentialProvider(harness().options);

      await provider.credentialFor(exchangeRequest());
      await provider.credentialFor(exchangeRequest({ subjectToken: 'a-different-subject-token' }));

      expect(exchangeCalls()).toHaveLength(2);
      expect(
        formOf(1).get('subject_token'),
        'and the second exchange carries the second token, not a replay of the first'
      ).toBe('a-different-subject-token');
    });

    it('treats an entry minted under another grant as a miss', async () => {
      replyOnce(200, credentialPayload(120));
      replyOnce(200, credentialPayload(120));
      const provider = createUpstreamCredentialProvider(harness().options);

      await provider.credentialFor(
        exchangeRequest({ grant: forgeActiveGrant({ subjectToken: SUBJECT_TOKEN }) })
      );
      const second = await provider.credentialFor(
        exchangeRequest({
          // Same token, new grant: the binding check passes and only the grant differs, so the
          // miss below is about the grant rather than about the token.
          grant: forgeActiveGrant({ subjectToken: SUBJECT_TOKEN, grantId: 'grant-b-2222' }),
        })
      );

      expect(
        exchangeCalls(),
        'the same token under a new grant is a new authorization: serving the old credential would carry the previous grant scope and role past the check meant to gate them'
      ).toHaveLength(2);
      expect(second.grantId).toBe('grant-b-2222');
    });

    it('states the ceiling once, by hand, so widening it cannot be byte-silent', () => {
      expect(
        MAX_CACHED_CREDENTIALS,
        'the two cases below LOOP this constant, so they track it rather than pin it: raising it to ten million changes no expectation and reddens nothing. The margin and the lifetime are each pinned by exact arithmetic elsewhere in this file; this is the one hand-written statement of the ceiling'
      ).toBe(1000);
    });

    it('refuses to insert past its ceiling rather than evicting a live credential', async () => {
      upstream.exchange(credentialPayload(120));
      const provider = createUpstreamCredentialProvider(harness().options);

      for (let index = 0; index < MAX_CACHED_CREDENTIALS; index += 1) {
        await provider.credentialFor(
          exchangeRequest({ subjectToken: `fill-token-${String(index)}` })
        );
      }
      const filled = exchangeCalls().length;
      expect(filled, 'the fill must really have exchanged once per token').toBe(
        MAX_CACHED_CREDENTIALS
      );

      // The first filled token is still inside its window, so it is still a hit.
      await provider.credentialFor(exchangeRequest({ subjectToken: 'fill-token-0' }));
      expect(exchangeCalls(), 'nothing already cached was pushed out').toHaveLength(filled);

      // One past the ceiling: exchanged, and deliberately not stored.
      await provider.credentialFor(exchangeRequest({ subjectToken: 'overflow-token' }));
      await provider.credentialFor(exchangeRequest({ subjectToken: 'overflow-token' }));
      expect(
        exchangeCalls(),
        'a miss costs one exchange and is always safe; an unbounded map of live bearer credentials is not'
      ).toHaveLength(filled + 2);
    });

    it('drops expired entries on write rather than waiting to be asked for them again', async () => {
      upstream.exchange(credentialPayload(120));
      const provider = createUpstreamCredentialProvider(harness().options);

      for (let index = 0; index < MAX_CACHED_CREDENTIALS; index += 1) {
        await provider.credentialFor(
          exchangeRequest({ subjectToken: `stale-token-${String(index)}` })
        );
      }

      // Everything above is now past its window. The next write sweeps it, so the ceiling is free.
      clockMs = START_MS + USABLE_WINDOW_MS;
      await provider.credentialFor(exchangeRequest({ subjectToken: 'fresh-token' }));
      const afterSweep = exchangeCalls().length;

      await provider.credentialFor(exchangeRequest({ subjectToken: 'fresh-token' }));
      expect(
        exchangeCalls(),
        'the fresh entry was stored, which it could not have been if the ceiling were still full of entries nothing had swept'
      ).toHaveLength(afterSweep);
    });

    it('refuses a grant that was checked against a different token, before reading the cache', async () => {
      replyOnce(200, credentialPayload(120));
      const { options, security } = harness();
      const provider = createUpstreamCredentialProvider(options);

      // Warm the cache legitimately, so a refusal below cannot be "there was nothing to serve".
      await provider.credentialFor(exchangeRequest());
      expect(exchangeCalls(), 'control: the legitimate pairing went through').toHaveLength(1);

      const error = await expectRejectedClass(
        provider.credentialFor(
          exchangeRequest({ grant: forgeActiveGrant({ subjectToken: 'some-other-token' }) })
        ),
        'upstream_failure',
        'grant checked against another token'
      );

      expect(
        errorCodeOf(error),
        'the brand proves a live check ran; the digest proves which token it ran for. Without this the two are independent and a caller can pair the grant for token B with token A'
      ).toBe('exchange_grant_token_mismatch');
      expect(
        security.map((event) => event.event),
        'recorded on the security channel: presenting a grant never checked for this token is the confused-deputy shape whatever caused it'
      ).toEqual(['upstream_credential_grant_token_mismatch']);
      expect(
        exchangeCalls(),
        'and it is refused BEFORE the cache is read, so a warm entry is not a way around the check'
      ).toHaveLength(1);
    });

    it('refuses the same mispairing on the direct exchange, not only through the cache', async () => {
      replyOnce(200, credentialPayload(120));

      const error = await expectRejectedClass(
        exchangeUpstreamCredential(
          harness().options,
          exchangeRequest({ grant: forgeActiveGrant({ subjectToken: 'some-other-token' }) })
        ),
        'upstream_failure',
        'mispaired grant on the direct path'
      );

      expect(errorCodeOf(error)).toBe('exchange_grant_token_mismatch');
      expect(exchangeCalls(), 'nothing reached the wire').toHaveLength(0);
    });

    it('cannot be handed a grant that no live check produced', () => {
      // @ts-expect-error `ActiveGrant` is branded with a symbol its own module does not export,
      // so this literal is not one. Deleting the brand makes this line compile and turns the
      // ordering guarantee back into a comment, which is what this case exists to catch.
      // `tokenDigest` is supplied deliberately: leaving it out would make the literal fail for a
      // second reason, and the directive would then stay green with the brand deleted.
      const forged: ActiveGrant = {
        grantId: GRANT_A,
        scopes: [],
        subject: USER_A,
        clientId: CLIENT_ID,
        tokenDigest: subjectTokenDigest(SUBJECT_TOKEN),
      };

      expect(
        forged,
        'a structural literal cannot reach credentialFor, so a cached credential cannot be reached without a fresh live grant check having succeeded first'
      ).toBeDefined();
    });
  });
});
