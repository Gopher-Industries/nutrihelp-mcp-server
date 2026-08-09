/**
 * Security suite: write confirmation replay and argument rebinding. Ticket 33 cases 8 and 9.
 *
 * WORDING CONFLICT: the ticket says "refused the second time", the plan says the repeat returns
 * the original result and writes nothing. Case 8 asserts the invariant both hold — exactly one
 * write reaches the backend.
 *
 * WILL PASS WHEN: ticket 48 lands the confirmation store and ticket 49 lands `record_meal`. It
 * also needs the backend meal-log write (tickets 46 and 47), which is WS2's work.
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
  type UpstreamMock,
  type WireCall,
} from '../../support/upstreamMock.ts';
import { expectToolResult } from '../../support/assertions.ts';
import {
  ANY_API_PATH,
  AUDIT_INGEST_PATH,
  CLIENT_ID,
  GRANT_A,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  NUTRIHELP_API_ORIGIN,
  SCOPES,
  USER_A,
} from '../../support/testEnv.ts';
import type { ToolResultView } from '../../support/mcpClient.ts';

const SMALL_MEAL = {
  items: [{ name: 'porridge', quantity: 1, unit: 'bowl' }],
  meal_type: 'breakfast',
  consumed_at: '2026-08-05T07:30:00Z',
};

/** Materially larger than SMALL_MEAL: this is the change a replayed token must not authorise. */
const LARGE_MEAL = {
  items: [
    { name: 'porridge', quantity: 6, unit: 'bowl' },
    { name: 'chocolate cake', quantity: 3, unit: 'slice' },
  ],
  meal_type: 'dinner',
  consumed_at: '2026-08-05T20:30:00Z',
};

let trustedKey: TestKeyPair;
let server: TestServer;
let upstream: UpstreamMock;
let token: string;

/**
 * NOT just `POST`: a write issued as `PUT` or `PATCH` would otherwise count as zero and pass
 * every assertion below. The route path is unfixed, so writes are classified by what makes them
 * dangerous — they mutated state at the API origin.
 */
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function writeCalls(): WireCall[] {
  return upstream.wireCalls().filter(
    (call) =>
      call.origin === NUTRIHELP_API_ORIGIN &&
      MUTATING_METHODS.has(call.method.toUpperCase()) &&
      // Audit ingest is a POST to the same origin and precedes every upstream call.
      !call.path.startsWith(AUDIT_INGEST_PATH)
  );
}

/**
 * PLAN GAP: the confirmation-token field name is fixed nowhere. The input schema names the
 * argument `confirmation_token`, so that is the primary lookup; camel case is accepted so this
 * fails over behaviour rather than over a naming choice.
 */
function expectConfirmationToken(view: ToolResultView, context: string): string {
  const structured = (view.structured ?? {}) as Record<string, unknown>;
  const candidate = structured.confirmation_token ?? structured.confirmationToken;

  expect(
    typeof candidate,
    `${context}: expected a pending action carrying a single-use confirmation token. Got: ${view.text.slice(0, 300)}`
  ).toBe('string');

  return typeof candidate === 'string' ? candidate : '';
}

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  token = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SCOPES.meallogWrite],
    sub: USER_A,
    grantId: GRANT_A,
    clientId: CLIENT_ID,
  });
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  upstream.introspect({
    active: true,
    scope: SCOPES.meallogWrite,
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
  // Answers any POST under /api/ so the test never depends on an unspecified route string.
  upstream.route({
    path: ANY_API_PATH,
    method: 'POST',
    status: 201,
    body: { data: { entry_id: 'meal-log-entry-1', energy_kj: 900, items: [{ name: 'porridge' }] } },
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

describe('two-step write confirmation', () => {
  /**
   * CASE 8. A confirmation used twice — no second write. All three legs: propose persists
   * nothing, confirm writes once, replay writes no second time.
   */
  it('writes once across a replayed confirmation token', async () => {
    // Leg 1: propose.
    const proposal = expectToolResult(
      await callTool(server, 'record_meal', SMALL_MEAL, token),
      'case 8 leg 1: record_meal with no confirmation token'
    );
    expect(
      writeCalls(),
      'case 8 leg 1: the first call resolves and summarises, and persists nothing'
    ).toHaveLength(0);

    // Server-side summary: a model-authored one would be the model describing its own write.
    expect(
      proposal.text,
      'case 8 leg 1: the pending action must carry a human-readable summary of the exact change'
    ).toMatch(/porridge/i);

    const confirmation = expectConfirmationToken(proposal, 'case 8 leg 1');

    // Leg 2: confirm. Exactly one write.
    const confirmed = expectToolResult(
      await callTool(
        server,
        'record_meal',
        { ...SMALL_MEAL, confirmation_token: confirmation },
        token
      ),
      'case 8 leg 2: record_meal with a matching confirmation token'
    );
    expect(
      writeCalls(),
      'case 8 leg 2: a confirmed write reaches the backend exactly once'
    ).toHaveLength(1);
    expect(confirmed.isError, 'case 8 leg 2: a matching confirmation is not an error').toBe(false);

    // Leg 3: replay the same token with the same arguments. Still one write.
    const replay = expectToolResult(
      await callTool(
        server,
        'record_meal',
        { ...SMALL_MEAL, confirmation_token: confirmation },
        token
      ),
      'case 8 leg 3: replayed confirmation token'
    );
    expect(
      writeCalls(),
      'case 8 leg 3: the confirmation token is single use and is the idempotency key. A replay must not produce a second meal-log entry'
    ).toHaveLength(1);

    // Require structured results on both sides before comparing — undefined === undefined otherwise.
    const returnedOriginalResult =
      confirmed.structured !== undefined &&
      replay.structured !== undefined &&
      JSON.stringify(replay.structured) === JSON.stringify(confirmed.structured);

    // Either branch is permitted: the token is refused here (single use), or absorbed
    // idempotently by the backing endpoint. A wire test cannot see which layer answered.
    expect(
      replay.isError || returnedOriginalResult,
      'case 8 leg 3: a replay is either refused or returns the original result. Never a protocol error or a crash, and "no structured result on either side" is not idempotency'
    ).toBe(true);
  });

  /**
   * CASE 9. A confirmation reused with different arguments, refused. Issued for one bowl of
   * porridge, presented against six bowls and three slices of cake.
   */
  it('rejects a confirmation token presented against different arguments', async () => {
    const proposal = expectToolResult(
      await callTool(server, 'record_meal', SMALL_MEAL, token),
      'case 9: record_meal proposing the small meal'
    );
    const confirmation = expectConfirmationToken(proposal, 'case 9');

    const replayed = expectToolResult(
      await callTool(
        server,
        'record_meal',
        { ...LARGE_MEAL, confirmation_token: confirmation },
        token
      ),
      'case 9: the small-meal token presented against the large meal'
    );

    expect(replayed.isError, 'case 9: an argument-hash mismatch is rejected').toBe(true);
    expect(
      writeCalls(),
      'case 9: nothing may be written when the confirmation does not match the resolved arguments'
    ).toHaveLength(0);

    // And the rejection must not leak the larger payload onward in any form.
    for (const call of upstream.wireCalls().filter((c) => c.origin === NUTRIHELP_API_ORIGIN)) {
      expect(
        call.body,
        'case 9: the unapproved arguments must not reach the backend at all'
      ).not.toContain('chocolate cake');
    }
  });
});
