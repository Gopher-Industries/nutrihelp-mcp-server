/**
 * Security suite: cross-user access through the dispatcher. Ticket 33 case 6.
 *
 * WILL PASS WHEN: dispatch lands in `src/tools/registry.ts` (ticket 25 covers listing only),
 * ticket 32 lands `get_meal_plan`, and ticket 28 lands the credentialed path in
 * `src/upstream/client.ts`. Also needs the backend's `GET /api/mealplan/me` (WS2).
 *
 * Introspection is stubbed active — ticket 59 owns it, and the revocation suite is where its
 * absence goes red.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../../scripts/makeToken.ts';
import {
  callTool,
  closeLocalDispatcher,
  startTestServer,
  type TestServer,
} from '../../support/mcpClient.ts';
import {
  installUpstreamMock,
  wireCallText,
  type UpstreamMock,
} from '../../support/upstreamMock.ts';
import { expectToolResult, expectWireCalls } from '../../support/assertions.ts';
import {
  CLIENT_ID,
  GRANT_A,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  MEALPLAN_LEGACY_PATH,
  MEALPLAN_ME_PATH,
  NUTRIHELP_API_ORIGIN,
  SCOPES,
  USER_A,
  USER_B,
} from '../../support/testEnv.ts';

/** Distinctive strings so "whose data came back" is a substring assertion, not a guess. */
const A_RECIPE = 'PORRIDGE-BELONGING-TO-USER-A';
const B_RECIPE = 'PAVLOVA-BELONGING-TO-USER-B';

let trustedKey: TestKeyPair;
let server: TestServer;
let upstream: UpstreamMock;
let tokenForUserA: string;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  tokenForUserA = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SCOPES.mealplanRead],
    sub: USER_A,
    grantId: GRANT_A,
    clientId: CLIENT_ID,
  });
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  upstream.introspect({
    active: true,
    scope: SCOPES.mealplanRead,
    sub: USER_A,
    client_id: CLIENT_ID,
    grant_id: GRANT_A,
  });
  upstream.exchange({
    access_token: 'exchanged-credential-for-user-a',
    issued_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_type: 'Bearer',
    expires_in: 120,
  });

  // The own-user route. Identity comes from the exchanged credential; the path carries none.
  // Query-tolerant by necessity, not style — see RouteSpec.path in upstreamMock.ts.
  upstream.route({
    path: new RegExp(`^${MEALPLAN_ME_PATH}(\\?.*)?$`),
    status: 200,
    body: {
      data: [
        {
          date: '2026-08-05',
          meal_type: 'breakfast',
          recipe_name: A_RECIPE,
          recipe_id: 11,
          energy_kj: 900,
        },
      ],
    },
  });

  // The route whose controller falls back to a request-supplied identifier. Primed with user
  // B's plan so reaching it at all is observable rather than a silent nothing.
  upstream.route({
    path: new RegExp(`^${MEALPLAN_LEGACY_PATH}(\\?.*)?$`),
    status: 200,
    body: {
      data: [
        {
          date: '2026-08-05',
          meal_type: 'breakfast',
          recipe_name: B_RECIPE,
          recipe_id: 22,
          energy_kj: 800,
        },
      ],
    },
  });

  server = await startTestServer();
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('one user reaching for another user data', () => {
  /**
   * CASE 6. One user attempting to reach another's data, refused. User A's grant and token,
   * asking for user B every way the argument surface allows.
   */
  it('serves only the token holder data and never touches the identity-fallback route', async () => {
    const response = await callTool(
      server,
      'get_meal_plan',
      {
        date: '2026-08-05',
        // Undeclared arguments; neither can alter identity. The model composes these, not
        // the user, so an untrusted party is choosing them.
        user_id: USER_B,
        userId: USER_B,
        targetUserId: USER_B,
      },
      tokenForUserA
    );

    // 1. The own-user route, and only it.
    const ownUserCalls = expectWireCalls(
      upstream.callsTo(MEALPLAN_ME_PATH),
      'case 6: get_meal_plan must call GET /api/mealplan/me'
    );
    const legacyCalls = upstream
      .callsTo(MEALPLAN_LEGACY_PATH)
      .filter((call) => !call.path.startsWith(MEALPLAN_ME_PATH));
    expect(
      legacyCalls,
      'case 6: the identity-fallback route resolves identity from the request and must never be called'
    ).toHaveLength(0);

    // 2. Scanned over every resource-origin call and the whole wire, not just the own-user
    // route's headers: a token in a query string is the same disclosure. The
    // authorization-server origin is excluded — that is where the token legitimately goes.
    for (const call of upstream.wireCalls().filter((c) => c.origin === NUTRIHELP_API_ORIGIN)) {
      expect(
        wireCallText(call),
        `case 6: the inbound MCP access token must never reach a resource endpoint. Leaked on ${call.method} ${call.fullUrl}`
      ).not.toContain(tokenForUserA);
    }

    // 3. No identifier for B on the wire, in the URL, the headers or the body.
    for (const call of ownUserCalls) {
      const wire = [call.fullUrl, JSON.stringify(call.headers), call.body].join('\n');
      expect(wire, `case 6: user B identifier reached the wire: ${call.fullUrl}`).not.toContain(
        USER_B
      );
    }

    // 4. And nothing of B's reaches the model.
    const view = expectToolResult(response, 'case 6: get_meal_plan for user A');
    expect(view.text, 'case 6: user B meal plan reached the model').not.toContain(B_RECIPE);
    expect(view.text, 'case 6: user A own meal plan should be returned').toContain(A_RECIPE);
  });
});
