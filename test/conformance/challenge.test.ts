/**
 * Wire form of 401 Bearer and pre-dispatch 403. Scope resolver is injected — no tool-to-scope
 * map exists yet, so the 403 branch is unreachable from production wiring alone.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { JWTPayload } from 'jose';
import {
  corruptSignature,
  createTestKeyPair,
  makeToken,
  type TestKeyPair,
} from '../../scripts/makeToken.ts';
import {
  closeLocalDispatcher,
  listTools,
  mcpRequest,
  startTestServer,
  type TestServer,
} from '../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../support/upstreamMock.ts';
import {
  expectInsufficientScopeChallenge,
  expectUnauthorizedChallenge,
} from '../support/assertions.ts';
import type { RequestRouting } from '../../src/transport/http.ts';
import {
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  RESOURCE_METADATA_URL,
  SCOPES,
  USER_A,
} from '../support/testEnv.ts';

let trustedKey: TestKeyPair;
let token: string;
let upstream: UpstreamMock;

/** Every routing value and claim set the injected resolver was handed, so a scope verdict computed
 *  from a value the guard should have refused is visible rather than merely improbable. */
let scopeArgs: { routing: RequestRouting; claims: JWTPayload }[];
let dispatches: number;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  token = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SCOPES.nutritionRead],
    sub: USER_A,
  });
});

beforeEach(() => {
  upstream = installUpstreamMock([trustedKey]);
  scopeArgs = [];
  dispatches = 0;
});

afterEach(async () => {
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

/**
 * A server whose injected resolver refuses whatever `requiredScope` names. It records what it was
 * asked about, which is the assertion that matters for the encoded-value case below.
 */
async function serverRequiring(requiredScope: string | undefined): Promise<TestServer> {
  return startTestServer({
    missingScopeFor: (routing: RequestRouting, claims: JWTPayload): string | undefined => {
      scopeArgs.push({ routing, claims });
      return requiredScope;
    },
    onDispatch: () => {
      dispatches += 1;
    },
  });
}

describe('insufficient scope on the wire', () => {
  // Optional and closed with `?.`: assigned inside each test, so if `serverRequiring` ever throws
  // the hook would otherwise fail on `undefined.close` and bury the real failure.
  let server: TestServer | undefined;

  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  it('answers 403 with the required scope and the metadata pointer', async () => {
    server = await serverRequiring(SCOPES.meallogWrite);

    const response = await mcpRequest(server, {
      method: 'tools/call',
      name: 'record_meal',
      params: { name: 'record_meal', arguments: {} },
      token,
    });

    expectInsufficientScopeChallenge(
      response,
      SCOPES.meallogWrite,
      'a verified credential whose grant does not carry the scope this operation needs'
    );
  });

  it('is 403 and never 401, so the client does not enter refresh-and-retry', async () => {
    server = await serverRequiring(SCOPES.meallogWrite);

    const response = await mcpRequest(server, {
      method: 'tools/call',
      name: 'record_meal',
      params: { name: 'record_meal', arguments: {} },
      token,
    });

    expect(
      response.status,
      'a 401 here sends the client to refresh, which mints the same scopes again and fails identically'
    ).not.toBe(401);
    expect(response.status).toBe(403);
    expect(response.challenge ?? '').not.toContain('invalid_token');
  });

  it('refuses before dispatch', async () => {
    server = await serverRequiring(SCOPES.meallogWrite);

    const response = await mcpRequest(server, {
      method: 'tools/call',
      name: 'record_meal',
      params: { name: 'record_meal', arguments: {} },
      token,
    });

    expect(dispatches, 'the scope refusal happens before the MCP handler is built').toBe(0);
    expect(
      response.rpc,
      'and there is no JSON-RPC envelope at all: the challenge header carries everything a client may act on'
    ).toBeUndefined();
  });

  it('reports the denied dispatch, because a refused authorization is security-relevant', async () => {
    server = await serverRequiring(SCOPES.meallogWrite);

    await mcpRequest(server, {
      method: 'tools/call',
      name: 'record_meal',
      params: { name: 'record_meal', arguments: {} },
      token,
    });

    expect(server.errors.map((error) => error.message)).toContain(
      `insufficient_scope.${SCOPES.meallogWrite}`
    );
  });

  /**
   * The encoded form must not reach a scope verdict. A requirement selected from an undecoded
   * routing value is a requirement selected from the wrong name, and the resolver never being
   * called is the only way to prove it did not happen — a 400 alone would not, because a
   * transport that consulted the resolver first and then refused would answer 400 too.
   */
  it('does not compute a scope verdict from an encoded routing value', async () => {
    server = await serverRequiring(SCOPES.meallogWrite);

    const response = await mcpRequest(server, {
      method: 'tools/call',
      nameHeader: '=?utf-8?B?cmVjb3JkX21lYWw=?=',
      params: { name: 'record_meal', arguments: {} },
      token,
    });

    expect(response.status, 'a malformed routing value is a bad request').toBe(400);
    expect(
      response.challenge,
      'and it carries no challenge of either kind: the credential was fine and the scope was never decided'
    ).toBeUndefined();
    expect(
      scopeArgs,
      'the scope resolver must never have been consulted about the encoded string'
    ).toHaveLength(0);
    expect(dispatches).toBe(0);
  });

  it('hands the resolver the plain routing values, not the body', async () => {
    server = await serverRequiring(SCOPES.meallogWrite);

    await mcpRequest(server, {
      method: 'tools/call',
      name: 'record_meal',
      params: { name: 'record_meal', arguments: {} },
      token,
    });

    expect(scopeArgs).toHaveLength(1);
    expect(scopeArgs[0]?.routing).toEqual({ method: 'tools/call', name: 'record_meal' });
    expect(scopeArgs[0]?.claims.sub, 'and the verified claims, not the raw token').toBe(USER_A);
  });

  /**
   * The granting direction. Without it, every assertion above is satisfied by an endpoint that
   * answers 403 to everything — including to the requests the grant does cover.
   */
  it('serves the request when the granted scopes suffice', async () => {
    server = await serverRequiring(undefined);

    const response = await listTools(server, token);

    expect(
      response.rpc?.id,
      'a positive discriminator: only the JSON-RPC dispatcher echoes the request id, and every refusal answers before it'
    ).toBe(1);
    expect(dispatches, 'the request reached the MCP handler').toBe(1);
    expect(response.status).not.toBe(401);
    expect(response.status).not.toBe(403);
    expect(response.challenge, 'a served request carries no challenge').toBeUndefined();
    expect(scopeArgs, 'the scope step ran and found nothing missing').toHaveLength(1);
  });
});

/**
 * Header values that yield no credential at all, so each must answer the challenge that starts the
 * connect flow rather than one claiming a token was invalid.
 *
 * UNSPECIFIED, and pinned here rather than decided here: the plan fixes the challenge for an
 * expired, wrong-audience, wrong-issuer or insufficiently-scoped credential, and says nothing about
 * a header that is present and unparseable. Answering the no-credential challenge is the coherent
 * reading — an unparseable header yields no credential, so there is no token to call invalid — but
 * it is a reading, and these rows should not become the specification by default. Raised for
 * adoption into the owning section.
 */
const UNPARSEABLE_HEADERS = [
  { label: 'a Basic credential', header: 'Basic dXNlcjpwYXNz' },
  { label: 'a bare token with no scheme', header: 'some-opaque-value' },
  { label: 'the scheme with nothing after it', header: 'Bearer' },
  { label: 'the scheme with only whitespace after it', header: 'Bearer   ' },
  { label: 'two credentials in one header', header: 'Bearer aaa bbb' },
  { label: 'a scheme that merely starts with Bearer', header: 'Bearerish abc' },
] as const;

describe('the 401 challenge on the wire', () => {
  let server: TestServer | undefined;

  /** Narrows the fixture. A `beforeEach` assignment cannot be seen by the type checker inside a
   *  test body, and an explicit throw here reports "the fixture did not start" rather than a
   *  `TypeError` on an unrelated line. */
  function live(): TestServer {
    if (server === undefined) throw new Error('the test server was not started');
    return server;
  }

  beforeEach(async () => {
    // A resolver that would refuse everything, so a 401 below proves the credential step answered
    // first rather than proving there was nothing to check.
    server = await serverRequiring(SCOPES.meallogWrite);
  });

  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  it('carries no error parameter when no credential was presented', async () => {
    const response = await listTools(live());

    expectUnauthorizedChallenge(response, 'no Authorization header at all');
    expect(
      response.challenge,
      'a client that presented nothing has nothing to correct: this response starts the connect flow'
    ).toBe(`Bearer resource_metadata="${RESOURCE_METADATA_URL}"`);
    expect(scopeArgs, 'and the scope step was never reached').toHaveLength(0);
  });

  it('carries error="invalid_token" when a credential failed to verify', async () => {
    const response = await listTools(live(), corruptSignature(token));

    expectUnauthorizedChallenge(response, 'a genuine token with its signature flipped');
    expect(response.challenge).toBe(
      `Bearer error="invalid_token", resource_metadata="${RESOURCE_METADATA_URL}"`
    );
    expect(scopeArgs).toHaveLength(0);
    expect(dispatches).toBe(0);
    expect(
      response.rpc,
      'no JSON-RPC envelope on a 401 either: the challenge header carries everything a client may act on, and the error taxonomy that owns model-facing payloads is not this layer to invent'
    ).toBeUndefined();
    expect(response.rawBody, 'and no body at all').toBe('');
  });

  it.each(UNPARSEABLE_HEADERS)(
    'answers the unauthenticated challenge for $label',
    async ({ header }) => {
      const response = await mcpRequest(live(), {
        method: 'tools/list',
        authorizationHeader: header,
      });

      expectUnauthorizedChallenge(response, `an unparseable Authorization header: ${header}`);
      expect(
        response.challenge,
        'an unparseable header yields no credential, so this is the same challenge as an absent one — it does not claim a token was invalid'
      ).toBe(`Bearer resource_metadata="${RESOURCE_METADATA_URL}"`);
      expect(scopeArgs).toHaveLength(0);
    }
  );

  it('matches the Bearer scheme case-insensitively', async () => {
    const response = await mcpRequest(live(), {
      method: 'tools/list',
      authorizationHeader: `bEaReR ${token}`,
    });

    expect(
      response.status,
      'the scheme is matched case-insensitively, so this credential IS extracted and reaches the scope step, which refuses it with 403'
    ).toBe(403);
    expect(scopeArgs, 'proof the credential was extracted and validated').toHaveLength(1);
  });

  /** `it.each([])` registers no tests and still exits 0, so emptying the table would delete these
   *  cases in silence. */
  it('keeps a floor under the unparseable-header table', () => {
    expect(
      UNPARSEABLE_HEADERS.length,
      'anti-vacuity: dropping rows from the unparseable-header table must fail this suite, not quieten it'
    ).toBeGreaterThanOrEqual(6);
  });
});
