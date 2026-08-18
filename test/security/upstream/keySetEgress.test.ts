/**
 * JWKS fetch goes through the one egress door. Does not mock `client.ts` — mocks the transport
 * beneath it, or uses a loopback server, so the wire is observable.
 *
 * The symbol-vs-string canary matters: `{ customFetch: fn }` is accepted and ignored, and a
 * reachable JWKS still verifies, so no other test would go red.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createRemoteJWKSet, customFetch } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  createTokenValidator,
  KeySetUnavailableError,
  type KeySetFetch,
} from '../../../src/auth/tokenValidator.ts';
import { CORRELATION_ID_HEADER, getWithoutCredential } from '../../../src/upstream/client.ts';
import {
  createTestKeyPair,
  makeToken,
  toJwks,
  type TestKeyPair,
} from '../../../scripts/makeToken.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import {
  AUTH_SERVER_ORIGIN,
  MCP_EXPECTED_ISSUER,
  MCP_JWKS_URL,
  MCP_RESOURCE_IDENTIFIER,
  ALL_SCOPES,
  USER_A,
} from '../../support/testEnv.ts';

const JWKS_PATH = new URL(MCP_JWKS_URL).pathname;

let trustedKey: TestKeyPair;
let upstream: UpstreamMock | undefined;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
});

afterEach(async () => {
  await upstream?.restore();
  upstream = undefined;
});

function goodToken(): Promise<string> {
  return makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_A,
  });
}

/** A fetcher that answers a valid key set and counts its calls. Answering correctly matters: a
 *  fetcher that failed would make "it was called" indistinguishable from "verification broke". */
function countingKeySetFetch(): { fetch: KeySetFetch; calls: () => number } {
  let calls = 0;
  const impl: KeySetFetch = () => {
    calls += 1;
    return Promise.resolve(
      new Response(JSON.stringify(toJwks([trustedKey])), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    );
  };
  return { fetch: impl, calls: () => calls };
}

describe('the fetch override the verification library actually honours', () => {
  it('routes key-set retrieval through the injected fetcher', async () => {
    const fetcher = countingKeySetFetch();

    const validator = createTokenValidator({
      jwksUrl: new URL(MCP_JWKS_URL),
      expectedIssuer: MCP_EXPECTED_ISSUER,
      expectedAudience: MCP_RESOURCE_IDENTIFIER,
      cacheMaxAgeMs: 300_000,
      requestDeadlineMs: 30_000,
      keySetFetch: fetcher.fetch,
    });

    const claims = await validator.validate(await goodToken());

    expect(claims.sub, 'the token verified, so the key set really was retrieved and used').toBe(
      USER_A
    );
    expect(
      fetcher.calls(),
      'the injected fetcher must be the one that ran. Zero here means the override was not honoured and the library used its own fetch, which is the whole egress boundary gone with every other test still green'
    ).toBeGreaterThan(0);
  });

  it('is ignored when spelled as a string key, which is why the symbol is not a style choice', async () => {
    // No JWKS route: ignored spelling falls through to jose's fetch and disableNetConnect refuses it.
    // Without the mock, the rejection would be DNS against `.test` — environment-dependent.
    upstream = installUpstreamMock([trustedKey], { jwks: 'unreachable' });

    const viaSymbol = countingKeySetFetch();
    const viaString = countingKeySetFetch();

    const symbolKeyed = createRemoteJWKSet(new URL(MCP_JWKS_URL), {
      [customFetch]: viaSymbol.fetch,
    });
    // The string spelling. Accepted at runtime, never consulted, and no error either way.
    const stringKeyed = createRemoteJWKSet(new URL(MCP_JWKS_URL), {
      customFetch: viaString.fetch,
    } as unknown as Parameters<typeof createRemoteJWKSet>[1]);

    await symbolKeyed({ alg: 'RS256', kid: trustedKey.kid }, undefined);

    // Refused by the mock rather than by the network. The rejection is the point: it proves the call
    // was attempted by something other than the counted fetcher.
    await expect(stringKeyed({ alg: 'RS256', kid: trustedKey.kid }, undefined)).rejects.toThrow();

    expect(
      upstream.wireCalls().length,
      'and it really did try to leave: the ignored spelling reached the dispatcher, which is what makes the zero count below "never consulted" rather than "never attempted"'
    ).toBeGreaterThan(0);

    expect(
      viaSymbol.calls(),
      'the symbol-keyed override is honoured, so this file is comparing two live spellings rather than one live and one broken fixture'
    ).toBeGreaterThan(0);
    expect(
      viaString.calls(),
      'and the string-keyed one is never called at all. This is what makes the spelling in the validator a control rather than a preference: getting it wrong is accepted, silent, and invisible to every other assertion'
    ).toBe(0);
  });
});

describe('the configured key-set lifetime', () => {
  function validatorWithLifetime(cacheMaxAgeMs: number) {
    return createTokenValidator({
      jwksUrl: new URL(MCP_JWKS_URL),
      expectedIssuer: MCP_EXPECTED_ISSUER,
      expectedAudience: MCP_RESOURCE_IDENTIFIER,
      cacheMaxAgeMs,
      requestDeadlineMs: 30_000,
    });
  }

  it('refetches once a short lifetime has elapsed', async () => {
    upstream = installUpstreamMock([trustedKey]);
    const validator = validatorWithLifetime(50);

    await validator.validate(await goodToken());
    expect(
      upstream.callsTo(JWKS_PATH).length,
      'the first verification fetches the key set, or there is no cache state for the wait below to expire'
    ).toBe(1);

    await new Promise((resolve) => setTimeout(resolve, 150));
    await validator.validate(await goodToken());

    expect(
      upstream.callsTo(JWKS_PATH).length,
      'the configured lifetime expired, so the set is fetched again. A validator that ignored the option would still be holding it under the library own ten-minute default and this would still read one'
    ).toBe(2);
  });

  it('does not refetch while a long lifetime is still running', async () => {
    upstream = installUpstreamMock([trustedKey]);
    const validator = validatorWithLifetime(300_000);

    await validator.validate(await goodToken());
    await new Promise((resolve) => setTimeout(resolve, 150));
    await validator.validate(await goodToken());

    expect(
      upstream.callsTo(JWKS_PATH).length,
      'the same wait, a lifetime that has not expired, and one fetch: the number passed is what decides, not the passage of time and not a fixed inherited default'
    ).toBe(1);
  });
});

describe('what the door puts on the wire', () => {
  it('drops caller credentials and keeps the headers a caller legitimately needs', async () => {
    upstream = installUpstreamMock([trustedKey]);

    const handedIn = new Headers({
      authorization: 'Bearer a-token-that-must-not-leave',
      cookie: 'session=a-cookie-that-must-not-leave',
      'proxy-authorization': 'Basic a-proxy-credential-that-must-not-leave',
      accept: 'application/jwk-set+json',
      'user-agent': 'nutrihelp-key-set-probe',
    });

    const response = await getWithoutCredential({
      url: `${AUTH_SERVER_ORIGIN}${JWKS_PATH}`,
      headers: handedIn,
      redirect: 'manual',
      deadlineMs: 30_000,
      correlationId: 'correlation-under-test',
    });

    expect(response.status, 'the request was answered, so there is a wire record to inspect').toBe(
      200
    );

    const [call] = upstream.callsTo(JWKS_PATH);
    expect(call, 'the request reached the wire, or every absence below is vacuous').toBeDefined();
    if (call === undefined) throw new Error('unreachable: the assertion above fails first');

    const sent = new Map(
      Object.entries(call.headers).map(([name, value]) => [
        name.toLowerCase(),
        Array.isArray(value) ? value.join(', ') : value,
      ])
    );

    for (const credential of ['authorization', 'cookie', 'proxy-authorization']) {
      expect(
        [...sent.keys()],
        `${credential} must not reach a host that has no business holding one. The inbound token is presented to exactly one party and a public document is fetched with nothing attached`
      ).not.toContain(credential);
    }

    // And the whole serialised request, in case a credential travelled under another name.
    const everythingSent = JSON.stringify(call.headers);
    for (const secret of [
      'a-token-that-must-not-leave',
      'a-cookie-that-must-not-leave',
      'a-proxy-credential-that-must-not-leave',
    ]) {
      expect(everythingSent, `no header may carry ${secret} under any name`).not.toContain(secret);
    }

    expect(
      sent.get('accept'),
      'the granting half: an allowlisted header the caller supplied does survive, so the absences above are a filter rather than a door that drops everything'
    ).toBe('application/jwk-set+json');
    expect(sent.get('user-agent'), 'and so does the second allowlisted one').toBe(
      'nutrihelp-key-set-probe'
    );
    expect(
      sent.get(CORRELATION_ID_HEADER),
      'the correlation identifier is added by the door, after filtering, so a caller can neither supply nor override it'
    ).toBe('correlation-under-test');
  });

  it('mints a correlation identifier when the caller has none', async () => {
    upstream = installUpstreamMock([trustedKey]);

    await getWithoutCredential({
      url: `${AUTH_SERVER_ORIGIN}${JWKS_PATH}`,
      redirect: 'manual',
      deadlineMs: 30_000,
      correlationId: undefined,
    });

    const [call] = upstream.callsTo(JWKS_PATH);
    expect(call).toBeDefined();
    const sent = new Map(
      Object.entries(call?.headers ?? {}).map(([name, value]) => [
        name.toLowerCase(),
        Array.isArray(value) ? value.join(', ') : value,
      ])
    );

    expect(
      sent.get(CORRELATION_ID_HEADER),
      'every outbound request carries one, so an absent caller value means the door mints it rather than omitting the header'
    ).toMatch(/[0-9a-f-]{36}/i);
  });

  it('filters by name, so a credential renamed to something unlisted is still dropped', async () => {
    upstream = installUpstreamMock([trustedKey]);

    await getWithoutCredential({
      url: `${AUTH_SERVER_ORIGIN}${JWKS_PATH}`,
      headers: new Headers({
        'x-my-own-authorization': 'Bearer another-credential-that-must-not-leave',
        authorization: 'Bearer still-must-not-leave',
      }),
      redirect: 'manual',
      deadlineMs: 30_000,
      correlationId: 'correlation-under-test',
    });

    const [call] = upstream.callsTo(JWKS_PATH);
    expect(call).toBeDefined();
    const everythingSent = JSON.stringify(call?.headers ?? {});

    expect(
      everythingSent,
      'an unlisted header is dropped whether or not it looks like a credential, which is what makes the allowlist complete against names nobody has thought of'
    ).not.toContain('another-credential-that-must-not-leave');
    expect(everythingSent).not.toContain('still-must-not-leave');
  });
});

describe('the request budget, enforced at the door', () => {
  it('surfaces a key set that outlasts the budget as a key-set failure', async () => {
    upstream = installUpstreamMock([trustedKey], {
      jwks: { status: 200, body: toJwks([trustedKey]), delayMs: 5_000 },
    });

    const validator = createTokenValidator({
      jwksUrl: new URL(MCP_JWKS_URL),
      expectedIssuer: MCP_EXPECTED_ISSUER,
      expectedAudience: MCP_RESOURCE_IDENTIFIER,
      cacheMaxAgeMs: 300_000,
      requestDeadlineMs: 300,
    });

    const started = Date.now();
    const outcome = await validator.validate(await goodToken()).then(
      () => 'resolved',
      (reason: unknown) => reason
    );
    const elapsed = Date.now() - started;

    expect(
      outcome,
      'the request must be refused rather than served: nothing was verified, because the key set never arrived'
    ).not.toBe('resolved');
    expect(
      outcome,
      `a budget overrun is a key-set failure, not a credential one — a credential answer would send the client refreshing against an endpoint that is not answering. Got: ${String(outcome)}`
    ).toBeInstanceOf(KeySetUnavailableError);
    expect(
      elapsed,
      'and it gave up on OUR budget rather than on the library inherited one, which is a factor of sixteen longer and would hold the request open past any deadline this server set'
    ).toBeLessThan(3_000);
  }, 20_000);
});

describe('redirects the door was not told to follow', () => {
  // Loopback server: MockAgent call history cannot show whether a redirect was followed.
  let server: Server;
  let origin: string;
  let redirectTargetHits: number;

  beforeAll(async () => {
    server = createServer((request, response) => {
      if (request.url === '/redirecting') {
        response.writeHead(302, { location: '/followed' });
        response.end();
        return;
      }
      redirectTargetHits += 1;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ followed: true }));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address() as AddressInfo;
    origin = `http://127.0.0.1:${String(address.port)}`;
  });

  afterEach(() => {
    redirectTargetHits = 0;
  });

  // Closed, because nothing else closes it: a `listen` in `beforeAll` with no matching teardown
  // holds the socket for the life of the worker.
  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  });

  it('does not follow one under the manual policy a key-set fetch asks for', async () => {
    redirectTargetHits = 0;

    const response = await getWithoutCredential({
      url: `${origin}/redirecting`,
      redirect: 'manual',
      deadlineMs: 30_000,
      correlationId: 'correlation-under-test',
    });

    expect(
      response.status,
      'the redirect is handed back rather than acted on, so the caller decides whether that location is one it will fetch from'
    ).toBe(302);
    expect(
      redirectTargetHits,
      'and the target was never requested. This is the assertion an omitted redirect key would break, silently, because fetch defaults to following'
    ).toBe(0);
  });

  it('does follow one when a caller asks for that', async () => {
    redirectTargetHits = 0;

    const response = await getWithoutCredential({
      url: `${origin}/redirecting`,
      redirect: 'follow',
      deadlineMs: 30_000,
      correlationId: 'correlation-under-test',
    });

    expect(response.status, 'followed through to the target').toBe(200);
    expect(
      redirectTargetHits,
      'the policy is honoured rather than hard-coded: the door passes the caller decision through, which is what makes writing it down meaningful'
    ).toBe(1);
  });
});
