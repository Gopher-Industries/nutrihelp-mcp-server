/**
 * Security suite: the identity deny-list on the way out. Ticket 33 case 7.
 *
 * The proof is the wire, not the return value: the client is never mocked, the transport
 * beneath it is, and every dispatch is recorded. The deployed backend honours these shapes
 * today, so a field that escapes the filter is not hypothetical.
 *
 * WILL PASS WHEN: ticket 28 lands `src/upstream/client.ts` with the frozen deny-list, and
 * tickets 26 and 32 land the two tools that drive it.
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
  USER_A,
  USER_B,
} from '../../support/testEnv.ts';

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
    access_token: 'exchanged-credential-for-user-a',
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
  server = await startTestServer();
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

    // Positive control: without it, a broken `../../../` walk makes existsSync return false and
    // the swap guard below passes silently forever.
    const knownModule = fileURLToPath(new URL('../../../src/transport/http.ts', import.meta.url));
    expect(existsSync(knownModule), 'the path walk used by the guard below must resolve').toBe(
      true
    );

    // Swap guard. testEnv.ts holds a COPY; file existence is used rather than a dynamic import
    // because the specifier cannot resolve while the file is absent (tsc TS2307).
    const clientModule = fileURLToPath(new URL('../../../src/upstream/client.ts', import.meta.url));
    expect(
      existsSync(clientModule),
      'src/upstream/client.ts now exists, so IDENTITY_DENY_LIST must be imported from it and the copy in testEnv.ts deleted. Until then a production list shorter than the copy passes every assertion here'
    ).toBe(false);
  });

  /**
   * CASE 7. A user ID smuggled into tool arguments, stripped and ignored.
   *
   * Checked across URL, headers and body: a filter that only cleaned the JSON body would still
   * ship the value in a query string. `expectWireCallsSince` stops a tool that simply failed
   * from looking like a tool that filtered.
   */
  it('never puts a deny-listed identity field on the wire', async () => {
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
          const wire = wireCallText(call);
          expect(
            wire,
            `case 7: the value of "${field}" reached the wire on ${tool}: ${call.fullUrl}`
          ).not.toContain(value);
          expect(
            wire,
            `case 7: the field name "${field}" reached the wire on ${tool}: ${call.fullUrl}`
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
