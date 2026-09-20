/**
 * **TICKET 59'S DONE-WHEN, INHERITED BY TICKET 87 AND DISCHARGED HERE.**
 *
 * *"A user disconnects, and the very next tool list AND tool call for that connection are refused
 * before any cached credential is read — tested with a credential deliberately warm in the cache —
 * while a second assistant connected by the same user keeps working."*
 *
 * Ticket 59 shipped the exchange and the cache and could not satisfy this, because nothing
 * dispatched through the provider: the criterion needs a **tool call**, a **warm cache** and a
 * **second assistant**, and all three need consumption. It was deferred by the lead onto whichever
 * ticket first wired the transport-to-registry seam. That is this one.
 *
 * **It is unfalsifiable with only `nutrition_lookup` registered.** That tool's backing endpoint
 * is public, so it skips exchange — a suite proving "no credential was read" against a
 * registry in which no credential *can* be read reads exactly like a passing control. So a
 * credentialed descriptor is injected, and the mutation below proves the assertions can fail.
 *
 * Everything real that can be real is real: the production revocation checker and credential
 * provider, at mocked endpoints, driven over the wire through the production `registerTools`.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../../scripts/makeToken.ts';
import {
  callTool,
  closeLocalDispatcher,
  listTools,
  startTestServer,
  type TestServer,
} from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectToolResult } from '../../support/assertions.ts';
// The header NAME from the door itself, so a rename cannot leave this suite asserting a header
// nothing sends. The VALUES compared below are read off the wire, not from any constant.
import { CORRELATION_ID_HEADER } from '../../../src/upstream/client.ts';
import { credentialedProbe, CREDENTIALED_TOOL_NAME } from '../../support/credentialedTool.ts';
import {
  AUTH_SERVER_ORIGIN,
  CLIENT_ID,
  GRANT_A,
  INTROSPECTION_PATH,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  SCOPES,
  TOKEN_EXCHANGE_PATH,
  USER_A,
} from '../../support/testEnv.ts';

/** The second assistant the same user connected. A different client and a different grant. */
const CLIENT_B = 'https://second-assistant.test/client.json';
const GRANT_B = 'grant-b-2222';

let trustedKey: TestKeyPair;
let tokenA: string;
let tokenB: string;
let upstream: UpstreamMock;
let server: TestServer;

/**
 * One scripted introspection answer, consumed once and in order. `introspect()` persists, so a
 * later call could never replace an earlier one — which is what makes "flip it to inactive"
 * need `once` routes rather than a second registration.
 */
function introspectOnce(payload: Record<string, unknown>): void {
  upstream.route({
    origin: AUTH_SERVER_ORIGIN,
    path: INTROSPECTION_PATH,
    method: 'POST',
    status: 200,
    body: payload,
    once: true,
  });
}

function activeFor(grantId: string, clientId: string): Record<string, unknown> {
  return {
    active: true,
    scope: SCOPES.nutritionRead,
    sub: USER_A,
    client_id: clientId,
    grant_id: grantId,
  };
}

/** What a disconnected connection introspects to. The only outcome that maps to 401. */
const DISCONNECTED = { active: false };

function exchangeCalls(): number {
  return upstream.callsTo(TOKEN_EXCHANGE_PATH).length;
}

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  tokenA = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SCOPES.nutritionRead],
    sub: USER_A,
    grantId: GRANT_A,
    clientId: CLIENT_ID,
  });
  tokenB = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SCOPES.nutritionRead],
    sub: USER_A,
    grantId: GRANT_B,
    clientId: CLIENT_B,
  });
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  // Persisted: the exchange endpoint always answers, so a second exchange would be VISIBLE on the
  // wire rather than failing. A cache that quietly stopped working must go red, not error.
  upstream.exchange({
    access_token: 'exchanged-upstream-credential-never-the-subject-token',
    issued_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_type: 'Bearer',
    expires_in: 120,
  });

  server = await startTestServer({
    revocation: 'live',
    credentials: 'live',
    registerRealTools: true,
    extraTools: [credentialedProbe],
  });
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('a disconnected grant, against a deliberately warm credential cache', () => {
  it('refuses the very next list AND call before any cached credential is read, while a second assistant keeps working', async () => {
    // 1. Warm the cache. A real exchange happens here and only here.
    introspectOnce(activeFor(GRANT_A, CLIENT_ID));
    const warming = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenA);

    expect(warming.status, 'the granting direction: without it every refusal below is free').toBe(
      200
    );
    expect(
      expectToolResult(warming, 'the warming call').structured,
      'and it really reached the handler WITH a credential — a 200 carrying a tool error would satisfy the status assertion alone'
    ).toEqual({ credentialed: true, grant_id: GRANT_A });
    expect(exchangeCalls(), 'one exchange, for the cold cache').toBe(1);
    expect(server.credentialRequests, 'and step 4 ran once').toHaveLength(1);

    // 2. Prove the cache is WARM rather than merely populated: a second successful call reads it
    //    and goes nowhere. Asserted on the wire, because `credentialFor` is called either way.
    introspectOnce(activeFor(GRANT_A, CLIENT_ID));
    const second = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenA);

    expect(second.status).toBe(200);
    expect(
      exchangeCalls(),
      'still one. A cache that had silently stopped working would read two here, and every refusal below would then be refusing against a COLD cache — which proves nothing'
    ).toBe(1);
    expect(
      server.introspections,
      'and two successful calls produced two live checks: a positive grant answer is never cached'
    ).toHaveLength(2);

    const beforeDisconnect = server.credentialRequests.length;

    // 3. The user disconnects that assistant. The very next tool LIST.
    introspectOnce(DISCONNECTED);
    const listAfter = await listTools(server, tokenA);

    expect(listAfter.status, 'an authenticated inactive answer is the only 401').toBe(401);
    expect(
      server.credentialRequests.length,
      'refused BEFORE any cached credential is read. The credential for this grant is sitting warm in the cache and was never consulted'
    ).toBe(beforeDisconnect);

    // 4. And the very next tool CALL.
    introspectOnce(DISCONNECTED);
    const callAfter = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenA);

    expect(callAfter.status).toBe(401);
    expect(
      server.credentialRequests.length,
      'the tool call is refused at step 2, so step 4 is never reached: a revoked grant can never reach an already-cached upstream credential'
    ).toBe(beforeDisconnect);
    expect(exchangeCalls(), 'and nothing went out to the token endpoint either').toBe(1);

    // 5. The same user's OTHER assistant is untouched. Revocation is per grant, not per user.
    introspectOnce(activeFor(GRANT_B, CLIENT_B));
    const other = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenB);

    expect(
      expectToolResult(other, 'the second assistant call').structured,
      'and the second assistant credential is minted under ITS OWN grant, not assistant A'
    ).toEqual({ credentialed: true, grant_id: GRANT_B });
    expect(
      other.status,
      'a second assistant the same user connected keeps working. Without this the suite is satisfied by an implementation that refuses everything after any disconnect'
    ).toBe(200);
    expect(
      exchangeCalls(),
      'and it gets its OWN credential rather than assistant A warm one: the cache is keyed on the subject token, so a second grant is a miss'
    ).toBe(2);
  });

  /**
   * **THE COUNTERFACTUAL, IN-SUITE, AND IT IS WHAT MAKES THE CASE ABOVE FALSIFIABLE.**
   *
   * Every assertion above is about something NOT happening, and an absence is satisfied by a path
   * that could never have happened. This is the SAME tool, the SAME token and the SAME server,
   * with exactly one thing changed: the live check answers `active` instead of `active: false`.
   * The credential IS then read. So "step 4 was never reached" is a property of step 2's answer,
   * not of a credentialed tool being unreachable from this suite.
   */
  it('reads the credential for that identical call when the grant is still live', async () => {
    introspectOnce(activeFor(GRANT_A, CLIENT_ID));
    const warming = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenA);
    expect(warming.status).toBe(200);
    const readsSoFar = server.credentialRequests.length;

    // The only difference from step 4 of the case above.
    introspectOnce(activeFor(GRANT_A, CLIENT_ID));
    const response = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenA);

    expect(response.status).toBe(200);
    expect(
      server.credentialRequests.length,
      'step 4 ran. Flip this one answer back to inactive and it does not, which states the rule as a difference rather than as an absence'
    ).toBe(readsSoFar + 1);
    expect(
      exchangeCalls(),
      'and it was served from the warm cache: the read happened, the wire did not'
    ).toBe(1);
  });

  /**
   * **THE CORRELATION ID, ASSERTED ACROSS TWO WIRE CALLS RATHER THAN AGAINST A FIXTURE.**
   *
   * The egress door mints its own id when the caller passes none — `options.correlationId ??
   * crypto.randomUUID()`, at both wire paths. So a seam that silently stopped threading the
   * transport's id would still put a well-formed `x-correlation-id` on every request, and every
   * single-call assertion would keep passing. What breaks is the only thing the id is FOR:
   * joining the records of one request.
   *
   * ONE tool call makes two outbound calls, through two different door functions. Comparing them
   * to each other needs no fixture and no injected constant — both values are read off the wire,
   * so neither side can be the thing that is wrong.
   */
  it('puts ONE correlation id on every outbound call a single request makes', async () => {
    introspectOnce(activeFor(GRANT_A, CLIENT_ID));
    const response = await callTool(server, CREDENTIALED_TOOL_NAME, {}, tokenA);

    expect(
      response.status,
      'the granting direction: a refused call makes fewer outbound calls'
    ).toBe(200);

    const idsByPath = (path: string): string[] =>
      upstream
        .callsTo(path)
        .map(
          (call) =>
            Object.entries(call.headers).find(
              ([name]) => name.toLowerCase() === CORRELATION_ID_HEADER
            )?.[1]
        )
        .map((value) => (Array.isArray(value) ? value[0] ?? '' : value ?? ''));

    const introspectionIds = idsByPath(INTROSPECTION_PATH);
    const exchangeIds = idsByPath(TOKEN_EXCHANGE_PATH);

    // Non-vacuity: an empty list satisfies every assertion below. This is a cold cache, so the
    // exchange really goes out rather than being served from memory.
    expect(introspectionIds, 'step 2 went out once').toHaveLength(1);
    expect(exchangeIds, 'and step 4 went out once, from a cold cache').toHaveLength(1);

    expect(
      introspectionIds[0],
      'the door mints a fallback when handed none, so an EMPTY id here would mean the header was absent entirely'
    ).toMatch(/\S/);

    expect(
      exchangeIds[0],
      'the SAME id on both. Two well-formed but different ids is exactly what a broken seam produces, and it is invisible to any assertion that looks at one call'
    ).toBe(introspectionIds[0]);
  });
});
