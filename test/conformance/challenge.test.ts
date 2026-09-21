/**
 * Wire form of 401 Bearer and pre-dispatch 403.
 *
 * Two kinds of case here and the difference matters. The first describe injects a resolver that
 * answers whatever the case names, so the transport's own behaviour — when it consults the scope
 * step, what it hands it, what it does with the answer — can be asserted without a map deciding it.
 * The last describe wires the **production** resolver and the real tool-to-scope map, so the 403
 * a deployed server actually answers is on the wire rather than described. Ticket 86.
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
  callTool,
  closeLocalDispatcher,
  listTools,
  mcpRequest,
  startTestServer,
  type TestServer,
} from '../support/mcpClient.ts';
import { forgeActiveGrant } from '../support/activeGrant.ts';
import { missingScopeFor } from '../../src/auth/scopes.ts';
import type { ActiveGrant } from '../../src/auth/revocation.ts';
import { installUpstreamMock, type UpstreamMock } from '../support/upstreamMock.ts';
import {
  expectInsufficientScopeChallenge,
  expectUnauthorizedChallenge,
} from '../support/assertions.ts';
import type { RequestRouting } from '../../src/transport/http.ts';
import {
  CLIENT_ID,
  GRANT_A,
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

/**
 * The production wiring, end to end: the real tool-to-scope map, the real resolver, and the real
 * transport. Nothing here names a required scope of its own — the map decides, which is what makes
 * these cases able to fail when the map changes.
 *
 * The grant is forged rather than introspected over the wire (that is `test/security/**`'s job);
 * what is real is the pairing — the gate reads the grant the checker returned for THIS request, and
 * the token is signed for the same connection id.
 */
describe('the frozen scope map on the wire', () => {
  let server: TestServer | undefined;

  afterEach(async () => {
    await server?.close();
    server = undefined;
  });

  /**
   * A server composed as `src/server.ts` composes it: the bare checker, and the frozen map wired
   * straight in. The grant introspection returns travels to the scope step as the resolver's third
   * argument — there is no hand-off record between them any more.
   */
  async function serverGrantingLive(liveScopes: readonly string[]): Promise<TestServer> {
    return startTestServer({
      revocation: {
        assertGrantActive: (): Promise<ActiveGrant> =>
          Promise.resolve(
            forgeActiveGrant({
              grantId: GRANT_A,
              scopes: liveScopes,
              subject: USER_A,
              clientId: CLIENT_ID,
            })
          ),
      },
      missingScopeFor,
      onDispatch: () => {
        dispatches += 1;
      },
    });
  }

  async function tokenScoped(scopes: readonly string[]): Promise<string> {
    return makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes,
      sub: USER_A,
      grantId: GRANT_A,
    });
  }

  it('serves a tool call the map covers and both sides grant', async () => {
    server = await serverGrantingLive([SCOPES.nutritionRead]);

    const response = await callTool(
      server,
      'nutrition_lookup',
      { query: 'oats' },
      await tokenScoped([SCOPES.nutritionRead])
    );

    expect(
      dispatches,
      'the granting direction, and the one an all-refusing implementation cannot fake'
    ).toBe(1);
    expect(response.status).not.toBe(403);
    expect(response.challenge, 'a served request carries no challenge').toBeUndefined();
  });

  /**
   * Asserts only that listing is not refused at the door, because the map gives `tools/list` no
   * requirement. It deliberately does not claim anything about the catalogue's contents: this
   * fixture registers no tools. **Scope-FILTERED listing is still ticket 25's**, and it is a
   * different claim from this one — `ctx.authInfo` is set now, so the filtering is buildable, but
   * nothing filters yet. Assert the listed names there, not here.
   */
  it('does not refuse tools/list for want of a scope, whatever the caller holds', async () => {
    server = await serverGrantingLive([]);

    const response = await listTools(server, await tokenScoped([]));

    expect(dispatches, 'the request reached the MCP handler').toBe(1);
    expect(response.status).not.toBe(403);
  });

  it('refuses a tool the granted scopes do not cover, naming the scope the map requires', async () => {
    server = await serverGrantingLive([SCOPES.nutritionRead]);

    const response = await callTool(
      server,
      'record_meal',
      {},
      await tokenScoped([SCOPES.nutritionRead])
    );

    expectInsufficientScopeChallenge(
      response,
      SCOPES.meallogWrite,
      'a grant that covers nutrition lookups and nothing else, calling the meal-log write'
    );
    expect(dispatches, 'and it is refused before the MCP handler is built').toBe(0);
  });

  /**
   * The half step 2 exists for, on the wire. The token is signed, unexpired, and says
   * `meallog:write`; the connection no longer does. Offline validation cannot see that.
   */
  it('refuses a signed scope the live grant no longer carries', async () => {
    server = await serverGrantingLive([SCOPES.nutritionRead]);

    const response = await callTool(
      server,
      'record_meal',
      {},
      await tokenScoped([SCOPES.nutritionRead, SCOPES.meallogWrite])
    );

    expectInsufficientScopeChallenge(
      response,
      SCOPES.meallogWrite,
      'a token minted before the user narrowed the connection: the claim still carries the scope and the grant does not'
    );
    expect(dispatches).toBe(0);
  });

  it('refuses when the token names a different connection than the grant that was checked', async () => {
    server = await serverGrantingLive([SCOPES.meallogWrite]);

    const response = await callTool(
      server,
      'record_meal',
      {},
      await makeToken({
        key: trustedKey,
        iss: MCP_EXPECTED_ISSUER,
        aud: MCP_RESOURCE_IDENTIFIER,
        scopes: [SCOPES.meallogWrite],
        sub: USER_A,
        grantId: 'grant-b-2222',
      })
    );

    expectInsufficientScopeChallenge(
      response,
      SCOPES.meallogWrite,
      'the live answer belongs to another connection, so there is no established grant for this one'
    );
    expect(dispatches).toBe(0);
  });
});
