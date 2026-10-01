/**
 * Security suite: write confirmation replay and argument rebinding.
 *
 * Ticket 33 cases 8 and 9.
 *
 * This suite uses:
 *   - the real production registerTools path
 *   - the real record_meal tool
 *   - the real Redis-backed ConfirmationStore
 *   - the real confirmation-token binding/replay logic
 *
 * Case 8:
 *   - proposal does not write
 *   - first confirmation writes exactly once
 *   - replay of the same token never causes a second write
 *
 * Case 9:
 *   - a confirmation token issued for one set of arguments cannot be
 *     reused with different arguments
 *   - the unapproved payload must never reach the backend
 */

import { createClient } from '@redis/client';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { connectConfirmationStore } from '../../../src/server.ts';
import { sha256, type ConfirmationStore } from '../../../src/consent/confirmation.ts';

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

/**
 * These tests require the same disposable local Redis instance used
 * by the existing recordMeal integration tests.
 */
const configured = process.env.MCP_CONFIRMATION_TEST_REDIS_URL;

if (configured === undefined) {
  console.warn(
    'SKIP confirmation security tests: MCP_CONFIRMATION_TEST_REDIS_URL is absent. ' +
      'CI supplies disposable Redis.'
  );
}

/**
 * The actual record_meal schema in src/tools/recordMeal.ts expects:
 *
 *   date
 *   meal_type
 *   food_name
 *   time
 */
const SMALL_MEAL = {
  date: '2026-08-05',
  meal_type: 'breakfast',
  food_name: 'porridge',
  time: '07:30:00',
};

const LARGE_MEAL = {
  date: '2026-08-05',
  meal_type: 'dinner',
  food_name: 'porridge and chocolate cake',
  time: '20:30:00',
};

let trustedKey: TestKeyPair;
let server: TestServer;
let upstream: UpstreamMock;
let token: string;

let raw: ReturnType<typeof createClient>;
let confirmationStore: Awaited<ReturnType<typeof connectConfirmationStore>>;

/**
 * Confirmation keys created by this test suite.
 *
 * We delete only these keys.
 * Never FLUSHDB because the Redis instance may contain data
 * belonging to another test.
 */
const confirmationKeys: string[] = [];

/**
 * NOT just POST.
 *
 * A write using PUT, PATCH or DELETE must also count as a mutation.
 */
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function writeCalls(): WireCall[] {
  return upstream
    .wireCalls()
    .filter(
      (call) =>
        call.origin === NUTRIHELP_API_ORIGIN &&
        MUTATING_METHODS.has(call.method.toUpperCase()) &&
        !call.path.startsWith(AUDIT_INGEST_PATH)
    );
}

/**
 * Wrap the real Redis confirmation store so this suite can track
 * and clean up only the confirmation keys it created.
 *
 * The wrapper deliberately preserves the exact ConfirmationStore
 * method signatures. This avoids the previous TypeScript errors
 * involving:
 *
 *   expiresAt: string vs number
 *
 * and:
 *
 *   JsonValue vs ConfirmationResult
 */
function tracked(store: ConfirmationStore): ConfirmationStore {
  return {
    issue: async (action) => {
      const proposal = await store.issue(action);

      confirmationKeys.push(`mcp:confirmation:v1:${sha256(proposal.confirmationToken)}`);

      return proposal;
    },

    execute: (action, write) => store.execute(action, write),
  };
}

/**
 * Extract the confirmation token returned by the production
 * record_meal confirmation flow.
 */
function expectConfirmationToken(view: ToolResultView, context: string): string {
  const structured = (view.structured ?? {}) as Record<string, unknown>;

  const candidate = structured.confirmation_token ?? structured.confirmationToken;

  expect(
    typeof candidate,
    `${context}: expected a pending action carrying a single-use confirmation token. ` +
      `Got: ${view.text.slice(0, 300)}`
  ).toBe('string');

  if (typeof candidate !== 'string') {
    throw new Error(`${context}: confirmation token was not returned as a string`);
  }

  return candidate;
}

beforeAll(async () => {
  if (configured === undefined) {
    return;
  }

  const parsed = new URL(configured);

  /**
   * These security tests must use disposable LOCAL Redis.
   *
   * Do not accidentally point this test suite at a production
   * or shared Redis instance.
   */
  if (!['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) {
    throw new Error('These security confirmation tests require disposable LOCAL Redis.');
  }

  raw = createClient({
    url: configured,
    socket: {
      reconnectStrategy: false,
    },
  });

  raw.on('error', () => undefined);

  await raw.connect();

  confirmationStore = await connectConfirmationStore(configured, {
    leaseMs: 60000,
  });

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
  if (configured === undefined) {
    return;
  }

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

  /**
   * record_meal.ts sends:
   *
   * POST /api/meallog/me
   *
   * and expects:
   *
   * {
   *   success: true,
   *   data: {
   *     id,
   *     date,
   *     meal_type,
   *     food_name,
   *     calories,
   *     protein,
   *     carbs,
   *     fat,
   *     fiber,
   *     sugar,
   *     sodium,
   *     time
   *   }
   * }
   *
   * ANY_API_PATH keeps this test independent of the exact
   * route matcher used by the upstream mock.
   */
  upstream.route({
    path: ANY_API_PATH,
    method: 'POST',
    status: 201,
    body: {
      success: true,
      data: {
        id: '1',
        date: SMALL_MEAL.date,
        meal_type: SMALL_MEAL.meal_type,
        food_name: SMALL_MEAL.food_name,
        calories: null,
        protein: null,
        carbs: null,
        fat: null,
        fiber: null,
        sugar: null,
        sodium: null,
        time: SMALL_MEAL.time,
      },
    },
  });

  /**
   * IMPORTANT:
   *
   * Use the real production registerTools() and inject the
   * real Redis-backed confirmation store.
   *
   * Previously this was omitted, which caused the test server
   * to use unavailableConfirmations and return:
   *
   *   "The service is temporarily unavailable."
   */
  server = await startTestServer({
    registerRealTools: true,
    confirmations: tracked(confirmationStore),
  });
});

afterEach(async () => {
  if (configured === undefined) {
    return;
  }

  await server.close();
  await upstream.restore();

  /**
   * Delete only keys created by this suite.
   */
  if (confirmationKeys.length > 0) {
    await raw.del(confirmationKeys.splice(0));
  }
});

afterAll(async () => {
  if (configured !== undefined) {
    confirmationStore.close();
    raw.destroy();
  }

  await closeLocalDispatcher();
});

describe.skipIf(configured === undefined)('two-step write confirmation', () => {
  /**
   * CASE 8
   *
   * A confirmation used twice must never produce a second
   * backend write.
   *
   * Three legs:
   *
   *   1. proposal -> zero backend writes
   *   2. confirmation -> exactly one backend write
   *   3. replay -> still exactly one backend write
   */
  it('writes once across a replayed confirmation token', async () => {
    /**
     * LEG 1: Proposal.
     *
     * No confirmation token is supplied.
     * record_meal must create a confirmation proposal and
     * must NOT write to the backend.
     */
    const proposal = expectToolResult(
      await callTool(server, 'record_meal', SMALL_MEAL, token),
      'case 8 leg 1: record_meal with no confirmation token'
    );

    expect(writeCalls(), 'case 8 leg 1: proposing a meal must not persist anything').toHaveLength(
      0
    );

    /**
     * The server-generated summary must contain the exact
     * pending change.
     */
    expect(
      proposal.text,
      'case 8 leg 1: the pending action must carry a human-readable summary of the exact change'
    ).toMatch(/porridge/i);

    const confirmation = expectConfirmationToken(proposal, 'case 8 leg 1');

    /**
     * LEG 2: Confirm.
     *
     * Send exactly the same meal arguments plus the
     * confirmation token.
     */
    const confirmed = expectToolResult(
      await callTool(
        server,
        'record_meal',
        {
          ...SMALL_MEAL,
          confirmation_token: confirmation,
        },
        token
      ),
      'case 8 leg 2: record_meal with a matching confirmation token'
    );

    expect(
      writeCalls(),
      'case 8 leg 2: a confirmed write must reach the backend exactly once'
    ).toHaveLength(1);

    expect(confirmed.isError, 'case 8 leg 2: a matching confirmation is not an error').toBe(false);

    /**
     * LEG 3: Replay the same token with the same arguments.
     *
     * The Redis confirmation store should return the stored
     * result instead of executing another backend write.
     */
    const replay = expectToolResult(
      await callTool(
        server,
        'record_meal',
        {
          ...SMALL_MEAL,
          confirmation_token: confirmation,
        },
        token
      ),
      'case 8 leg 3: replayed confirmation token'
    );

    expect(
      writeCalls(),
      'case 8 leg 3: replaying a confirmation token must not produce a second backend write'
    ).toHaveLength(1);

    /**
     * The production Redis store returns the original result
     * on replay.
     *
     * Require both structured results before comparing them.
     * Otherwise undefined === undefined could incorrectly pass.
     */
    const returnedOriginalResult =
      confirmed.structured !== undefined &&
      replay.structured !== undefined &&
      JSON.stringify(replay.structured) === JSON.stringify(confirmed.structured);

    /**
     * Either behaviour is acceptable according to the test
     * contract:
     *
     *   - reject the replay, or
     *   - return the original stored result.
     *
     * What is never acceptable is a second backend write.
     */
    expect(
      replay.isError || returnedOriginalResult,
      'case 8 leg 3: replay must either be refused or return the original result; it must never perform a second write'
    ).toBe(true);
  });

  /**
   * CASE 9
   *
   * A confirmation token issued for one set of arguments
   * must not authorize a different set of arguments.
   *
   * Token:
   *
   *   breakfast + porridge
   *
   * Attempted reuse:
   *
   *   dinner + porridge + chocolate cake
   */
  it('rejects a confirmation token presented against different arguments', async () => {
    /**
     * First create a confirmation for the SMALL_MEAL.
     */
    const proposal = expectToolResult(
      await callTool(server, 'record_meal', SMALL_MEAL, token),
      'case 9: record_meal proposing the small meal'
    );

    const confirmation = expectConfirmationToken(proposal, 'case 9');

    /**
     * Now attempt to use the small-meal token with
     * completely different arguments.
     */
    const replayed = expectToolResult(
      await callTool(
        server,
        'record_meal',
        {
          ...LARGE_MEAL,
          confirmation_token: confirmation,
        },
        token
      ),
      'case 9: the small-meal token presented against the large meal'
    );

    /**
     * record_meal converts confirmation mismatch into a
     * confirmation-required error/pending response.
     */
    expect(replayed.isError, 'case 9: an argument-hash mismatch must be rejected').toBe(true);

    /**
     * Most importantly, the large meal must NEVER reach
     * the backend.
     */
    expect(
      writeCalls(),
      'case 9: nothing may be written when confirmation arguments do not match'
    ).toHaveLength(0);

    /**
     * Also inspect every request sent to the NutriHelp API
     * and ensure the unapproved "chocolate cake" payload
     * was never transmitted.
     */
    for (const call of upstream.wireCalls().filter((c) => c.origin === NUTRIHELP_API_ORIGIN)) {
      expect(
        call.body,
        'case 9: the unapproved arguments must not reach the backend'
      ).not.toContain('chocolate cake');
    }
  });
});
