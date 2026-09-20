/**
 * Security suite: **the inbound token reaches exactly one party** — the issuer that signed it —
 * and only ever as the `subject_token` of an RFC 8693 exchange. It is never a bearer credential
 * to anything, and it never reaches the data backend in any request location.
 *
 * Presenting it to its own issuer is not passthrough: that party already holds the key and is
 * the only one entitled to interpret it. Every other recipient is a leak.
 *
 * **How this is proved, and why the shape matters.** The real module, the real
 * `src/upstream/client.ts` (never mocked — the deny-list and the header allowlist live inside
 * it) and a real `undici` `MockAgent` under it. Assertions read `wireCalls()`, so they are about
 * bytes that reached a dispatcher rather than about arguments a function was called with.
 *
 * ⚠️ **The load-bearing case is the whole-transcript scan.** The three narrower ones are all
 * satisfied by an exchange pointed at the wrong host: only the scan asks who the **recipient**
 * was, rather than what the request looked like. Proved by mutation — repointing the exchange
 * URL at the data backend leaves the other three green and turns that one red.
 *
 * The `ActiveGrant` this suite hands `credentialFor` comes from a real introspection against the
 * mocked endpoint, not from the test-only forge. The point of the parameter is that only a live
 * check can produce one, and a forged value would assert the opposite.
 */

import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createUpstreamCredentialProvider,
  type ExchangeOptions,
  type UpstreamCredential,
} from '../../../src/auth/upstreamToken.ts';
import { createRevocationChecker, type ActiveGrant } from '../../../src/auth/revocation.ts';
import { McpError } from '../../../src/errors.ts';
import { fetchUpstream } from '../../../src/upstream/client.ts';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../../scripts/makeToken.ts';
import {
  installUpstreamMock,
  wireCallText,
  type UpstreamMock,
  type WireCall,
} from '../../support/upstreamMock.ts';
import {
  ALL_SCOPES,
  AUTH_SERVER_ORIGIN,
  CLIENT_ID,
  FOODDATA_SEARCH_PATH,
  GRANT_A,
  INTROSPECTION_PATH,
  MCP_AUTH_SERVER_URL,
  MCP_CLIENT_ID,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  NUTRIHELP_API_BASE_URL,
  USER_B,
  RESOURCE_METADATA_URL,
  TOKEN_EXCHANGE_PATH,
  USER_A,
} from '../../support/testEnv.ts';

const INTROSPECTION_URL = `${AUTH_SERVER_ORIGIN}${INTROSPECTION_PATH}`;

/**
 * Where the exchange is sent. Derived exactly as `src/server.ts` derives it, so a mutation that
 * repoints it is a one-line change to a value with a name rather than a rewrite.
 */
const TOKEN_EXCHANGE_URL = new URL(TOKEN_EXCHANGE_PATH, MCP_AUTH_SERVER_URL).href;

const CORRELATION_ID = 'invariant-3-correlation';
const DEADLINE_MS = 5_000;

/** The second grant, for the ordering case. A different authorization over the same token. */
const GRANT_B = 'grant-b-2222';

/** Distinct from the subject token by construction, so "different string" is checkable. */
const EXCHANGED_CREDENTIAL = 'exchanged-upstream-credential-b41f';

let signingKey: TestKeyPair;
let assertionKey: { readonly privateKey: KeyObject; readonly publicKey: KeyObject };

/** A structurally perfect MCP access token. Signed for real; never hand-written. */
let subjectToken: string;

/** A second real token, so "a grant for another token" is a real pairing rather than a fixture. */
let otherSubjectToken: string;

/** Produced by a real live introspection, which is the only thing that can produce one. */
let grant: ActiveGrant;
let grantUnderB: ActiveGrant;
/** Live-checked, genuinely — just against `otherSubjectToken` rather than `subjectToken`. */
let grantForOtherToken: ActiveGrant;

let upstream: UpstreamMock;

function exchangeOptions(tokenEndpointUrl = TOKEN_EXCHANGE_URL): ExchangeOptions {
  return {
    tokenEndpointUrl,
    clientId: MCP_CLIENT_ID,
    clientAssertionKey: assertionKey.privateKey,
    now: () => Date.now(),
    logOperational: () => undefined,
    logSecurity: () => undefined,
  };
}

/**
 * A real `ActiveGrant`, obtained under a throwaway mock whose transcript is then discarded.
 * Introspection legitimately carries the subject token to the same issuer, and counting it here
 * would blur the question this suite asks — which is what the exchange call does with it.
 */
async function liveGrant(grantId: string, token = subjectToken): Promise<ActiveGrant> {
  const bootstrap = installUpstreamMock([signingKey]);
  try {
    bootstrap.introspect({
      active: true,
      scope: ALL_SCOPES.join(' '),
      sub: USER_A,
      client_id: CLIENT_ID,
      grant_id: grantId,
      aud: MCP_RESOURCE_IDENTIFIER,
      iss: MCP_EXPECTED_ISSUER,
    });

    const checker = createRevocationChecker({
      introspectionUrl: INTROSPECTION_URL,
      clientId: MCP_CLIENT_ID,
      clientAssertionKey: assertionKey.privateKey,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      negativeCacheMaxAgeMs: 0,
      now: () => Date.now(),
      logOperational: () => undefined,
      logSecurity: () => undefined,
    });

    return await checker.assertGrantActive({
      token,
      correlationId: CORRELATION_ID,
      deadlineMs: DEADLINE_MS,
    });
  } finally {
    await bootstrap.restore();
  }
}

beforeAll(async () => {
  signingKey = await createTestKeyPair('mcp-signing-key-1');
  assertionKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  subjectToken = await makeToken({
    key: signingKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_A,
    grantId: GRANT_A,
    clientId: CLIENT_ID,
  });

  otherSubjectToken = await makeToken({
    key: signingKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_B,
    grantId: GRANT_B,
    clientId: CLIENT_ID,
  });

  grant = await liveGrant(GRANT_A);
  grantUnderB = await liveGrant(GRANT_B);
  grantForOtherToken = await liveGrant(GRANT_B, otherSubjectToken);
});

beforeEach(() => {
  upstream = installUpstreamMock([signingKey]);
});

afterEach(async () => {
  await upstream.restore();
});

/**
 * One exchange, then one ordinary data call to the backend. The data call is what makes the
 * transcript scan non-vacuous: without a non-authorization-server request in the transcript,
 * "the token appears nowhere outside the issuer" is a claim about an empty set.
 */
async function exchangeThenCallBackend(
  tokenEndpointUrl = TOKEN_EXCHANGE_URL
): Promise<UpstreamCredential> {
  upstream.exchange({
    access_token: EXCHANGED_CREDENTIAL,
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: 120,
  });
  upstream.route({
    path: new RegExp(`^${FOODDATA_SEARCH_PATH}`),
    status: 200,
    body: { items: [] },
  });

  const provider = createUpstreamCredentialProvider(exchangeOptions(tokenEndpointUrl));
  const credential = await provider.credentialFor({
    subjectToken,
    grant,
    correlationId: CORRELATION_ID,
    deadlineMs: DEADLINE_MS,
  });

  await fetchUpstream({
    baseUrl: NUTRIHELP_API_BASE_URL,
    path: FOODDATA_SEARCH_PATH,
    declaredParameters: ['food'],
    toolArguments: { food: 'apple' },
    deadlineMs: DEADLINE_MS,
    correlationId: CORRELATION_ID,
  });

  return credential;
}

/** The one request that went to the exchange path, whatever host answered it. */
function exchangeCall(): WireCall {
  const calls = upstream.wireCalls().filter((call) => call.path === TOKEN_EXCHANGE_PATH);
  expect(calls, 'exactly one exchange must have reached the wire').toHaveLength(1);
  const call = calls[0];
  if (call === undefined) throw new Error('no exchange request reached the wire');
  return call;
}

/** URL, query, headers and body as one searchable string: a field can be smuggled in any. */
function everythingSentIn(call: WireCall): string {
  return [wireCallText(call), JSON.stringify(call.searchParams)].join('\n');
}

function occurrencesOf(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

describe('the inbound token goes to its issuer, as a subject token, and nowhere else', () => {
  it('sends no Authorization header at all on the exchange', async () => {
    await exchangeThenCallBackend();

    const names = Object.keys(exchangeCall().headers).map((name) => name.toLowerCase());

    expect(
      names,
      'the exchange authenticates with private_key_jwt in the body. An Authorization header here would be the inbound token forwarded as a bearer credential, which is the exact thing this invariant forbids'
    ).not.toContain('authorization');
    expect(names, 'and no ambient credential either').not.toContain('cookie');
    expect(
      names,
      'control: headers really were captured, so the absences above are about a request that happened'
    ).toContain('content-type');
  });

  it('carries the token exactly once on that request, under the name subject_token', async () => {
    await exchangeThenCallBackend();

    const call = exchangeCall();
    const form = new URLSearchParams(call.body);

    expect(form.get('subject_token'), 'verbatim, to the party that signed it').toBe(subjectToken);
    expect(
      [...form.entries()].filter(([, value]) => value.includes(subjectToken)).map(([name]) => name),
      'one field and one field only. A second copy under another name is a second disclosure, and the endpoint would honour whichever it reads first'
    ).toEqual(['subject_token']);
    expect(
      occurrencesOf(everythingSentIn(call), subjectToken),
      'and once across the whole request: not in the URL, not in the query, not in a header'
    ).toBe(1);
  });

  it('never puts the token in any request to anything that is not the authorization server', async () => {
    await exchangeThenCallBackend();

    const foreign = upstream.wireCalls().filter((call) => call.origin !== AUTH_SERVER_ORIGIN);

    expect(
      foreign,
      'control: at least one request must have gone somewhere other than the authorization server, or this scan is a claim about an empty set'
    ).not.toHaveLength(0);

    for (const call of foreign) {
      expect(
        everythingSentIn(call),
        `the inbound token reached ${call.origin}${call.path}. This is the assertion about the RECIPIENT rather than about the shape of the request: the three cases above are all satisfied by a correctly shaped exchange sent to the wrong host`
      ).not.toContain(subjectToken);
    }
  });

  it('hands back a credential that is a different string from the token it exchanged', async () => {
    const credential = await exchangeThenCallBackend();

    expect(
      credential.accessToken,
      'returning the subject token would satisfy every "an exchange happened" assertion while forwarding the inbound credential to the backend under a new name'
    ).not.toBe(subjectToken);
    expect(credential.accessToken).toBe(EXCHANGED_CREDENTIAL);
    expect(
      subjectToken.length,
      'control: the subject token is a real signed token, so the inequality above is not about an empty string'
    ).toBeGreaterThan(100);
  });

  /**
   * The runtime half, and the one that survives into a running server.
   *
   * Both grants here are real: each came back from an actual introspection. The only thing wrong
   * is the **pairing** — a grant genuinely checked for one token, presented alongside a different
   * one. No type system sees that, so nothing but this check stands between a caller mixing up
   * two in-flight requests and an upstream credential minted for the wrong user.
   */
  it('refuses a real grant that was checked against a different real token', async () => {
    upstream.exchange({
      access_token: EXCHANGED_CREDENTIAL,
      token_type: 'Bearer',
      expires_in: 120,
    });

    const provider = createUpstreamCredentialProvider(exchangeOptions());

    let refused: unknown;
    await provider
      .credentialFor({
        subjectToken,
        grant: grantForOtherToken,
        correlationId: CORRELATION_ID,
        deadlineMs: DEADLINE_MS,
      })
      .then(
        () => undefined,
        (error: unknown) => {
          refused = error;
        }
      );

    expect(
      refused,
      'a grant checked for another token must be refused, and refused at RUNTIME: the brand is a compile-time guard and a compile-time guard is absent from a running server'
    ).toBeInstanceOf(McpError);
    expect(
      upstream.wireCalls().filter((call) => call.path === TOKEN_EXCHANGE_PATH),
      'and nothing was exchanged, so no credential for the other token was ever minted'
    ).toHaveLength(0);

    expect(
      grantForOtherToken.grantId,
      'control: both values are real grants from real introspections, so this case is about the PAIRING and not about one of them being a fixture'
    ).toBe(GRANT_B);
    expect(otherSubjectToken, 'control: and the two tokens really differ').not.toBe(subjectToken);
  });

  /**
   * The structural half of the ordering rule. `credentialFor` takes the value a live grant check returns,
   * and `ActiveGrant` is branded by the module that mints it — so a caller that skipped
   * introspection has nothing to pass. The runtime half is that a credential cached under one
   * grant is not served to another: the same token under a new authorization is a new
   * authorization, and reusing the old credential would carry the previous grant's scope and
   * role past the check meant to gate them.
   */
  it('will not serve a credential cached under one grant to a different grant', async () => {
    upstream.exchange({
      access_token: EXCHANGED_CREDENTIAL,
      token_type: 'Bearer',
      expires_in: 120,
    });

    const provider = createUpstreamCredentialProvider(exchangeOptions());
    const base = {
      subjectToken,
      correlationId: CORRELATION_ID,
      deadlineMs: DEADLINE_MS,
    } as const;

    await provider.credentialFor({ ...base, grant });
    await provider.credentialFor({ ...base, grant });
    expect(
      upstream.wireCalls().filter((call) => call.path === TOKEN_EXCHANGE_PATH),
      'control: the second call for the same grant is a cache hit, so the count below is about the grant and not about caching being off'
    ).toHaveLength(1);

    await provider.credentialFor({ ...base, grant: grantUnderB });

    expect(
      upstream.wireCalls().filter((call) => call.path === TOKEN_EXCHANGE_PATH),
      'a new grant over the same token must exchange again'
    ).toHaveLength(2);
    expect(grant.grantId, 'control: the two grants really are different').not.toBe(
      grantUnderB.grantId
    );
  });
});
