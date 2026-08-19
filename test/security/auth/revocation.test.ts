/**
 * Security suite: access after disconnection. Ticket 33 case 5.
 *
 * WILL PASS WHEN: ticket 59 lands `src/auth/revocation.ts`, wired between offline token
 * validation and the scope check. Tokens here are structurally valid so only the grant check
 * can refuse them.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../../scripts/makeToken.ts';
import {
  callTool,
  closeLocalDispatcher,
  listTools,
  startTestServer,
  type McpResponse,
  type TestServer,
} from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectNotAnAuthChallenge, expectUnauthorizedChallenge } from '../../support/assertions.ts';
import {
  ALL_SCOPES,
  CLIENT_ID,
  FOODDATA_SEARCH_PATH,
  GRANT_A,
  INTROSPECTION_PATH,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  MEALPLAN_ME_PATH,
  TOKEN_EXCHANGE_PATH,
  USER_A,
} from '../../support/testEnv.ts';

let trustedKey: TestKeyPair;
let server: TestServer;
let upstream: UpstreamMock;
/** Structurally perfect: offline validation cannot fault it, so only the live grant check can. */
let tokenOfRevokedGrant: string;

/** Distinct `grant_id` per attempt: a permitted negative cache could otherwise reduce the
 *  introspection count below three and fail correct code. */
let revokedGrantTokens: string[];

async function mintRevokedToken(grantId: string): Promise<string> {
  return makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_A,
    grantId,
    clientId: CLIENT_ID,
  });
}

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  tokenOfRevokedGrant = await mintRevokedToken(GRANT_A);
  revokedGrantTokens = await Promise.all([
    mintRevokedToken(`${GRANT_A}-list`),
    mintRevokedToken(`${GRANT_A}-lookup`),
    mintRevokedToken(`${GRANT_A}-mealplan`),
  ]);
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  server = await startTestServer();
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('a grant the user disconnected', () => {
  /**
   * CASE 5. User who disconnected, refused on the next call. All three surfaces, including
   * the two that need no credential.
   */
  it('refuses tools/list, nutrition_lookup and get_meal_plan before any upstream access', async () => {
    // Authenticated introspection, explicit negative: the ONE outcome mapped to 401.
    upstream.introspect({ active: false });

    const [listToken, lookupToken, mealPlanToken] = revokedGrantTokens;

    const attempts: readonly [string, () => Promise<McpResponse>][] = [
      ['tools/list', () => listTools(server, listToken)],
      [
        'nutrition_lookup (public backing endpoint, still checked)',
        () => callTool(server, 'nutrition_lookup', { food: 'apple' }, lookupToken),
      ],
      [
        'get_meal_plan (credentialed backing endpoint)',
        () => callTool(server, 'get_meal_plan', { date: '2026-08-05' }, mealPlanToken),
      ],
    ];

    for (const [label, send] of attempts) {
      expectUnauthorizedChallenge(await send(), `case 5: revoked grant on ${label}`);
    }

    // A 401 from an offline shortcut would pass the assertions above with revocation absent.
    expect(
      upstream.callsTo(INTROSPECTION_PATH).length,
      'case 5: live RFC 7662 introspection runs on every request, including tools/list'
    ).toBe(attempts.length);

    // The ordering guarantee as an absence: a revoked grant never reaches a cached credential.
    expect(
      upstream.callsTo(TOKEN_EXCHANGE_PATH),
      'case 5: token exchange must not be reached after an inactive grant'
    ).toHaveLength(0);
    expect(
      [...upstream.callsTo(MEALPLAN_ME_PATH), ...upstream.callsTo(FOODDATA_SEARCH_PATH)],
      'case 5: no backing endpoint is called after an inactive grant'
    ).toHaveLength(0);
  });

  /**
   * COMPANION TO CASE 5, not one of the ticket's ten. A 401 here would loop every client
   * through refresh-and-retry during an authorization-server outage.
   */
  it('does not present an introspection outage as an authentication failure', async () => {
    upstream.introspect({ error: 'server_error' }, 503);

    const response = await listTools(server, tokenOfRevokedGrant);

    // First on purpose: "not a 401" is satisfied by a server that never checked anything.
    expect(
      upstream.callsTo(INTROSPECTION_PATH).length,
      'companion to case 5: live introspection must have run before the mapping can be judged'
    ).toBe(1);

    // Denied, not served. Without this a fail-open server that ignores the 503 and serves
    // tools/list passes: 200 is not 401, and tools/list never exchanges even on success.
    expect(
      response.status,
      `an unresolvable introspection result must deny the request. Got HTTP ${String(response.status)}`
    ).toBeGreaterThanOrEqual(400);

    expectNotAnAuthChallenge(response, 'companion to case 5: introspection returned 503');

    // And it still fails closed: the request must not reach exchange or a backing endpoint.
    expect(
      upstream.callsTo(TOKEN_EXCHANGE_PATH),
      'companion to case 5: an unresolvable grant check fails before exchange'
    ).toHaveLength(0);
  });

  /**
   * The malformed case: a missing `active` member read as truthy is a total bypass. */
  it('fails closed on an introspection response carrying no explicit active result', async () => {
    upstream.introspect({ scope: ALL_SCOPES.join(' '), sub: USER_A });

    const response = await listTools(server, tokenOfRevokedGrant);

    // Same guard: a 4xx from an endpoint that never introspected proves nothing.
    expect(
      upstream.callsTo(INTROSPECTION_PATH).length,
      'live introspection must have run before its result can be judged malformed'
    ).toBe(1);

    expect(
      response.status,
      `a response with no explicit active result must not permit dispatch. Got HTTP ${String(response.status)}`
    ).toBeGreaterThanOrEqual(400);

    // Denied, and as the retryable class rather than a challenge.
    expectNotAnAuthChallenge(response, 'companion to case 5: introspection body had no `active`');

    expect(
      upstream.callsTo(TOKEN_EXCHANGE_PATH),
      'a missing `active` member must not be read as active'
    ).toHaveLength(0);
  });
});
