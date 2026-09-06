/**
 * Security suite: access after disconnection. Ticket 33 case 5.
 *
 * Tokens are structurally valid, so only the live grant check can refuse them. Built with the
 * real checker (`revocation: 'live'`), not the fixture default — so introspection counts are wire.
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
  // Real production checker at the mocked introspection endpoint; other suites use always-active.
  server = await startTestServer({ revocation: 'live' });
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('a grant the user disconnected', () => {
  /** Case 5: disconnected user refused on the next call — including surfaces needing no credential. */
  it('refuses tools/list, nutrition_lookup and get_meal_plan before any upstream access', async () => {
    // Authenticated explicit active:false — the one outcome mapped to 401.
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

    // Offline shortcut would pass the 401s above with revocation absent.
    expect(
      upstream.callsTo(INTROSPECTION_PATH).length,
      'case 5: live RFC 7662 introspection runs on every request, including tools/list'
    ).toBe(attempts.length);

    // Revoked grant must not reach a cached credential.
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
   * Companion to case 5: a 401 on AS outage would refresh-loop every client.
   */
  it('does not present an introspection outage as an authentication failure', async () => {
    upstream.introspect({ error: 'server_error' }, 503);

    const response = await listTools(server, tokenOfRevokedGrant);

    // First: "not a 401" alone is satisfied by a server that never checked.
    expect(
      upstream.callsTo(INTROSPECTION_PATH).length,
      'companion to case 5: live introspection must have run before the mapping can be judged'
    ).toBe(1);

    // Denied, not served — fail-open that ignores 503 and returns 200 also passes "not 401".
    expect(
      response.status,
      `an unresolvable introspection result must deny the request. Got HTTP ${String(response.status)}`
    ).toBeGreaterThanOrEqual(400);

    expectNotAnAuthChallenge(response, 'companion to case 5: introspection returned 503');

    expect(
      upstream.callsTo(TOKEN_EXCHANGE_PATH),
      'companion to case 5: an unresolvable grant check fails before exchange'
    ).toHaveLength(0);
  });

  /** Missing `active` read as truthy is a total bypass. */
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
