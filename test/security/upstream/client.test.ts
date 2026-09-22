/**
 * Security suite: the identity deny-list on the way out. Ticket 33 case 7.
 *
 * The proof is the wire, not the return value: the client is never mocked, the transport
 * beneath it is, and every dispatch is recorded. The deployed backend honours these shapes
 * today, so a field that escapes the filter is not hypothetical.
 *
 * INTENTIONALLY RED until a `get_meal_plan` tool is registered on the server this suite starts:
 * `nutrition_lookup` passes, and the `get_meal_plan` leg finds no request on the wire. Do not skip
 * or delete: it goes green when that tool lands.
 */

import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
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
  type WireCall,
} from '../../support/upstreamMock.ts';
import { expectWireCallsSince } from '../../support/assertions.ts';
import {
  ALL_SCOPES,
  CLIENT_ID,
  FOODDATA_SEARCH_PATH,
  GRANT_A,
  IDENTITY_DENY_LIST,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  MEALPLAN_ME_PATH,
  NUTRIHELP_API_ORIGIN,
  USER_A,
  USER_B,
} from '../../support/testEnv.ts';
import { contract, handler, inputSchema } from '../../../src/tools/nutritionLookup.ts';

/** Same normalisation the deny-list matches with: `USER_ID`, `user-id` and `userId` are one name. */
function normalizeName(name: string): string {
  return name.replace(/[^a-z0-9]/gi, '').toLowerCase();
}

function collectJsonKeys(value: unknown, into: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value) collectJsonKeys(item, into);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, nested] of Object.entries(value)) {
      into.add(normalizeName(key));
      collectJsonKeys(nested, into);
    }
  }
}

/**
 * Every name a field could travel under: query keys, header names and body keys, normalised.
 * Names are compared whole, because a substring search over the wire text matches `user`
 * inside the `user-agent` header the runtime adds to every request.
 */
function wireFieldNames(call: WireCall): string[] {
  const names = new Set<string>();
  for (const key of Object.keys(call.searchParams)) names.add(normalizeName(key));
  for (const key of Object.keys(call.headers)) names.add(normalizeName(key));
  if (call.body !== '') {
    try {
      collectJsonKeys(JSON.parse(call.body), names);
    } catch {
      for (const key of new URLSearchParams(call.body).keys()) names.add(normalizeName(key));
    }
  }
  return [...names];
}

/** URL, header values and body as one searchable string; header names are left out. */
function wireTextWithoutHeaderNames(call: WireCall): string {
  return [call.fullUrl, ...Object.values(call.headers).map(String), call.body].join('\n');
}

/** Distinctive values, so a leak is unambiguous rather than a coincidental substring. */
const SMUGGLED_VALUE = 'SMUGGLED-USER-B-c0ffee';
const SMUGGLED_EMAIL = 'smuggled-victim@nutrihelp.test';

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
    scopes: ALL_SCOPES,
    sub: USER_A,
    grantId: GRANT_A,
    clientId: CLIENT_ID,
  });
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  upstream.introspect({
    active: true,
    scope: ALL_SCOPES.join(' '),
    sub: USER_A,
    client_id: CLIENT_ID,
    grant_id: GRANT_A,
  });
  upstream.exchange({
    access_token: 'exchanged-credential-for-a',
    issued_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_type: 'Bearer',
    expires_in: 120,
  });
  upstream.route({
    path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
    status: 200,
    body: { data: [{ food_name: 'Apple', energy_kj: 218, protein_g: 0.3 }] },
  });
  upstream.route({
    path: new RegExp(`^${MEALPLAN_ME_PATH}(\\?.*)?$`),
    status: 200,
    body: {
      data: [
        {
          date: '2026-08-05',
          meal_type: 'breakfast',
          recipe_name: 'Porridge',
          recipe_id: 11,
          energy_kj: 900,
        },
      ],
    },
  });
  server = await startTestServer((mcp) => {
    mcp.registerTool(
      'nutrition_lookup',
      { ...contract, inputSchema },
      handler({
        nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
        remainingBudgetMs: (): number => 30_000,
        correlationId: 'client-security-suite-correlation-id',
      })
    );
  });
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

/**
 * `nutrition_lookup` is here deliberately: its endpoint is public and takes no credential,
 * which is where "the deny-list does not matter here" is most tempting and most wrong.
 */
const DRIVEN_TOOLS = [
  { tool: 'nutrition_lookup', args: { food: 'apple' }, backingPath: FOODDATA_SEARCH_PATH },
  { tool: 'get_meal_plan', args: { date: '2026-08-05' }, backingPath: MEALPLAN_ME_PATH },
] as const;

describe('a user identifier smuggled into tool arguments', () => {
  /** Direct deny-list check: the wire test below cannot see it because zod strips undeclared keys. */
  it('declares every required identity field, and is not silently empty', () => {
    const REQUIRED = [
      'user_id',
      'userId',
      'email',
      'targetUserId',
      'targetEmail',
      'target_user_id',
      'target_email',
    ] as const;

    expect(
      IDENTITY_DENY_LIST.length,
      'an empty deny-list passes every wire-absence assertion in this file'
    ).toBeGreaterThan(0);

    for (const field of REQUIRED) {
      expect(
        IDENTITY_DENY_LIST as readonly string[],
        `"${field}" is stripped on the way out`
      ).toContain(field);
    }

    // Positive control: the static path used for the on-disk source-of-truth check must resolve.
    const knownModule = fileURLToPath(new URL('../../../src/transport/http.ts', import.meta.url));
    expect(existsSync(knownModule), 'the path walk used by the guard below must resolve').toBe(
      true
    );

    // The real upstream client is the source of truth for the deny-list, so the file must exist.
    // Swap guard: file existence because a dynamic import won't resolve while the file is absent.
    const clientModule = fileURLToPath(new URL('../../../src/upstream/client.ts', import.meta.url));
    expect(
      existsSync(clientModule),
      'src/upstream/client.ts must exist and be the source of truth for IDENTITY_DENY_LIST'
    ).toBe(true);
  });

  /**
   * CASE 7. A user ID smuggled into tool arguments, stripped and ignored.
   *
   * Checked across URL, headers and body: a filter that only cleaned the JSON body would still
   * ship the value in a query string. `expectWireCallsSince` stops a tool that simply failed
   * from looking like a tool that filtered.
   */
  it('never puts a deny-listed identity field on the wire', async () => {
    // The name check must fire on a real key and stay quiet on a header that merely contains one.
    const synthetic: WireCall = {
      method: 'POST',
      origin: NUTRIHELP_API_ORIGIN,
      path: FOODDATA_SEARCH_PATH,
      fullUrl: `${NUTRIHELP_API_ORIGIN}${FOODDATA_SEARCH_PATH}?user=x`,
      searchParams: { user: 'x' },
      headers: { 'user-agent': 'node' },
      body: JSON.stringify({ nested: { target_email: 'x' } }),
    };
    expect(wireFieldNames(synthetic)).toContain(normalizeName('user'));
    expect(wireFieldNames(synthetic)).toContain(normalizeName('target_email'));
    expect(wireFieldNames({ ...synthetic, searchParams: {}, body: '' })).not.toContain(
      normalizeName('user')
    );
    expect(
      wireTextWithoutHeaderNames({ ...synthetic, fullUrl: '', searchParams: {}, body: '' })
    ).not.toContain('user');
    expect(
      wireTextWithoutHeaderNames({ ...synthetic, body: '{"p":"{\\"user_id\\":1}"}' })
    ).toContain('user_id');

    for (const { tool, args, backingPath } of DRIVEN_TOOLS) {
      for (const field of IDENTITY_DENY_LIST) {
        const value = field.toLowerCase().includes('email') ? SMUGGLED_EMAIL : SMUGGLED_VALUE;

        // Snapshot before the call: the guard must prove *this* iteration reached the wire.
        const before = upstream.callsTo(backingPath).length;

        await callTool(server, tool, { ...args, [field]: value }, token);

        const calls = expectWireCallsSince(
          upstream.callsTo(backingPath),
          before,
          `case 7: ${tool} with ${field} injected must still reach ${backingPath}. Nothing on the wire makes the absence assertion vacuous`
        );

        for (const call of calls) {
          expect(
            wireCallText(call),
            `case 7: the value of "${field}" reached the wire on ${tool}: ${call.fullUrl}`
          ).not.toContain(value);
          expect(
            wireFieldNames(call),
            `case 7: the field name "${field}" reached the wire on ${tool}: ${call.fullUrl}`
          ).not.toContain(normalizeName(field));
          // The whole-name check misses a name inside a path, a bracketed or compound key, a
          // header value or a nested JSON string; a substring search catches those, and leaves
          // out only header names, where `user-agent` would match `user`.
          expect(
            wireTextWithoutHeaderNames(call),
            `case 7: the field name "${field}" appears in the URL, a header value or the body on ${tool}: ${call.fullUrl}`
          ).not.toContain(field);
        }
      }
    }

    // The identity that does reach the wire arrives as the exchanged credential, not a
    // parameter.
    for (const call of upstream.callsTo(MEALPLAN_ME_PATH)) {
      expect(
        call.fullUrl,
        'case 7: the own-user route takes identity from the credential, never from the URL'
      ).not.toContain(USER_A);
      expect(call.fullUrl, 'case 7: no identifier for another user in the URL').not.toContain(
        USER_B
      );
    }
  });
});
