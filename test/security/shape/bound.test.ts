/**
 * Security suite: bounded model-facing output. Ticket 33 case 10.
 *
 * The byte ceiling is 32 KiB and truncation sets `truncated` + `truncation_note`. Both were
 * unspecified when this suite was written, so neither is asserted here yet.
 *
 * WILL PASS WHEN: ticket 29 lands `src/shape/bound.ts` and ticket 32 lands `get_meal_plan`.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../../scripts/makeToken.ts';
import {
  callTool,
  closeLocalDispatcher,
  startTestServer,
  type TestServer,
} from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectToolResult } from '../../support/assertions.ts';
import {
  CLIENT_ID,
  GRANT_A,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  MEALPLAN_ME_PATH,
  SCOPES,
  USER_A,
} from '../../support/testEnv.ts';

/** One date per call, six meal entries maximum. */
const MEAL_ENTRY_CEILING = 6;

/** Field values that must be stripped by the allowlist projection, each unmistakable. */
const LEAKED_EMAIL = 'oversharing-victim@nutrihelp.test';
const LEAKED_INTERNAL_ID = 'INTERNAL-ROW-ID-9f8e7d';
const LEAKED_NOTE = 'FREE-TEXT-CLINICAL-NOTE-DO-NOT-SHIP';

/** What a non-production backend hands back: 500 rows, undeclared fields, `_contractWarnings`. */
const HUGE_UPSTREAM_BODY = {
  success: true,
  _contractWarnings: ['response shape drifted from the OpenAPI document'],
  data: Array.from({ length: 500 }, (_, index) => ({
    date: '2026-08-05',
    meal_type: 'breakfast',
    recipe_name: `Recipe number ${String(index)}`,
    recipe_id: index,
    energy_kj: 900 + index,
    // Everything below is outside the projection and must not reach the model.
    user_id: USER_A,
    email: LEAKED_EMAIL,
    internal_row_id: LEAKED_INTERNAL_ID,
    clinical_note: LEAKED_NOTE,
    ingredients: Array.from({ length: 40 }, (_, i) => `ingredient-${String(i)}-${'x'.repeat(64)}`),
  })),
};

const HUGE_UPSTREAM_BYTES = JSON.stringify(HUGE_UPSTREAM_BODY).length;

let trustedKey: TestKeyPair;
let server: TestServer;
let upstream: UpstreamMock;
let token: string;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  token = await makeToken({
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
  upstream.route({
    path: new RegExp(`^${MEALPLAN_ME_PATH}(\\?.*)?$`),
    status: 200,
    body: HUGE_UPSTREAM_BODY,
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

describe('a huge upstream response', () => {
  /**
   * CASE 10. A huge upstream response, truncated rather than passed on. */
  it('bounds, projects and marks the result rather than passing it through', async () => {
    const view = expectToolResult(
      await callTool(server, 'get_meal_plan', { date: '2026-08-05' }, token),
      'case 10: get_meal_plan against an upstream returning 500 rows'
    );

    const modelFacing = view.text;

    // 1. Row ceiling. Assert `entries` by name — a structural array search can pick the wrong one.
    const structured = (view.structured ?? {}) as Record<string, unknown>;
    const rawEntries: unknown = structured.entries;
    expect(
      Array.isArray(rawEntries),
      'case 10: get_meal_plan returns its projected rows in a member named `entries`. A different name is a contract change'
    ).toBe(true);
    const entries: unknown[] = Array.isArray(rawEntries) ? rawEntries : [];
    expect(
      entries.length,
      `case 10: get_meal_plan is capped at ${String(MEAL_ENTRY_CEILING)} meal entries, enforced after the upstream response. Got ${String(entries.length)}`
    ).toBeLessThanOrEqual(MEAL_ENTRY_CEILING);
    expect(
      entries.length,
      'case 10: the projection must still return the entries it kept, or the ceiling assertion above is vacuous'
    ).toBeGreaterThan(0);

    // 2. No pass-through.
    expect(
      modelFacing.length,
      `case 10: an upstream body is never returned verbatim. Upstream sent ${String(HUGE_UPSTREAM_BYTES)} bytes`
    ).toBeLessThan(HUGE_UPSTREAM_BYTES / 10);

    // 3. Allowlist projection.
    expect(
      modelFacing,
      'case 10: `_contractWarnings` is backend response-contract variance and is not in the get_meal_plan projection'
    ).not.toContain('_contractWarnings');
    expect(
      modelFacing,
      'case 10: `ingredients` is explicitly excluded from the get_meal_plan output schema'
    ).not.toContain('ingredient-0');
    expect(
      modelFacing,
      'case 10: a free-text field the endpoint added later must be stripped by the allowlist, not survive a denylist'
    ).not.toContain(LEAKED_NOTE);

    // 4. No internal identifiers or contact fields.
    expect(modelFacing, 'case 10: no email reaches the model').not.toContain(LEAKED_EMAIL);
    expect(modelFacing, 'case 10: no internal identifier reaches the model').not.toContain(
      LEAKED_INTERNAL_ID
    );
    expect(modelFacing, 'case 10: the user identifier is not a returned field').not.toContain(
      USER_A
    );

    // 5. Dropping rows is explicit, not silent. PLAN GAP: the marker wording attaches to the
    // BYTE ceiling; this is the ROW ceiling, where a count plus a deep link is preferred. So
    // assert the property, not the verb.
    const signalsDroppedRows =
      /truncat|showing|of 500|\b500\b|more\b|remaining|view all|see all/i.test(modelFacing) ||
      typeof structured.total === 'number' ||
      typeof structured.total_count === 'number' ||
      typeof structured.view_all === 'string';
    expect(
      signalsDroppedRows,
      `case 10: 500 rows became at most ${String(MEAL_ENTRY_CEILING)} and nothing told the model. Dropping data silently is forbidden — expected a truncation marker, a total, or a deep link. Model-facing text: ${modelFacing.slice(0, 300)}`
    ).toBe(true);
  });
});
