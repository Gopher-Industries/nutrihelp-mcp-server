/** Real MCP HTTP + JWT validation + Ticket 59 introspection + Redis/Lua + HTTP write adapter.
 * Authorization server/backend HTTP are intercepted; exchange and audit are explicit adapters.
 * This is not a claim that the currently unavailable deployment integrations are implemented.
 */
import { generateKeyPairSync } from 'node:crypto';
import { createClient } from '@redis/client';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { registerTools } from '../../src/tools/registry.ts';
import { createRevocationChecker } from '../../src/auth/revocation.ts';
import { missingRecordMealScope } from '../../src/auth/writeContext.ts';
import { connectConfirmationStore } from '../../src/auth/confirmationStore.ts';
import { sha256 } from '../../src/auth/confirmationArguments.ts';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../scripts/makeToken.ts';
import { installUpstreamMock, type UpstreamMock } from '../support/upstreamMock.ts';
import {
  callTool,
  closeLocalDispatcher,
  listTools,
  startTestServer,
  toolResult,
  type McpResponse,
  type TestServer,
} from '../support/mcpClient.ts';
import {
  AUTH_SERVER_ORIGIN,
  INTROSPECTION_PATH,
  MCP_CLIENT_ID,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  RESOURCE_METADATA_URL,
  SCOPES,
} from '../support/testEnv.ts';
import { activeGrant, meal, mealConfig, servicesFor, storedMeal } from '../support/recordMeal.ts';

let key: TestKeyPair;
let raw: ReturnType<typeof createClient>;
let first: Awaited<ReturnType<typeof connectConfirmationStore>>;
let second: Awaited<ReturnType<typeof connectConfirmationStore>>;
let mock: UpstreamMock;
let services: ReturnType<typeof servicesFor>;
let server: TestServer;
let otherServer: TestServer;
let token: string;
const keys: string[] = [];
const cleanup: (() => void)[] = [];
const configured = process.env.MCP_CONFIRMATION_TEST_REDIS_URL;
if (configured === undefined)
  console.warn(
    'SKIP record_meal Redis integration: MCP_CONFIRMATION_TEST_REDIS_URL is absent. CI supplies disposable Redis.'
  );

describe.skipIf(configured === undefined)('record_meal Redis gate', () => {
  const assertionKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;

  beforeAll(async () => {
    const url = configured;
    if (!url || !['localhost', '127.0.0.1', '[::1]'].includes(new URL(url).hostname)) {
      throw new Error('Set MCP_CONFIRMATION_TEST_REDIS_URL to disposable LOCAL Redis.');
    }
    raw = createClient({ url, socket: { reconnectStrategy: false } });
    cleanup.push(() => {
      if (raw.isOpen) raw.destroy();
    });
    raw.on('error', () => {
      /* Operations expose connection failures to the test. */
    });
    await raw.connect();
    first = await connectConfirmationStore(url, { leaseMs: 60_000 });
    cleanup.push(first.close);
    second = await connectConfirmationStore(url, { leaseMs: 60_000 });
    cleanup.push(second.close);
    key = await createTestKeyPair('record-meal-test');
  });

  beforeEach(async () => {
    mock = installUpstreamMock([key]);
    services = servicesFor(first);
    // Delegate to the real Ticket 59 checker; the HTTP intercept is the only substitute.
    const checker = createRevocationChecker({
      introspectionUrl: AUTH_SERVER_ORIGIN + INTROSPECTION_PATH,
      clientId: MCP_CLIENT_ID,
      clientAssertionKey: assertionKey,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      negativeCacheMaxAgeMs: 0,
      now: Date.now,
      logOperational: () => {
        /* Assertions inspect wire responses. */
      },
      logSecurity: () => {
        /* No production logging in tests. */
      },
    });
    services.revocation.assertGrantActive.mockImplementation((request) =>
      checker.assertGrantActive(request)
    );
    server = await startTestServer({
      missingScopeFor: missingRecordMealScope,
      revocation: services.revocation,
      configureServer: (instance, context) => {
        registerTools(instance, context, mealConfig, services);
      },
    });
    otherServer = await startTestServer({
      missingScopeFor: missingRecordMealScope,
      revocation: services.revocation,
      configureServer: (instance, context) => {
        registerTools(instance, context, mealConfig, { ...services, confirmations: second });
      },
    });
    token = await tokenFor();
  });

  afterEach(async () => {
    await server.close();
    await otherServer.close();
    await mock.restore();
    if (keys.length) await raw.del(keys.splice(0));
  });

  afterAll(async () => {
    for (const close of cleanup) close();
    await closeLocalDispatcher();
  });

  function tokenFor(
    change: { sub?: string; clientId?: string; grantId?: string; scopes?: string[] } = {}
  ) {
    return makeToken({
      key,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      sub: activeGrant.subject,
      clientId: activeGrant.clientId,
      grantId: activeGrant.grantId,
      scopes: [SCOPES.meallogWrite],
      ...change,
    });
  }

  function active(times?: number, changes: Record<string, unknown> = {}) {
    const body = {
      active: true,
      sub: activeGrant.subject,
      client_id: activeGrant.clientId,
      grant_id: activeGrant.grantId,
      scope: SCOPES.meallogWrite,
      ...changes,
    };
    if (times === undefined) mock.introspect(body);
    else
      for (let i = 0; i < times; i++)
        mock.route({
          origin: AUTH_SERVER_ORIGIN,
          path: INTROSPECTION_PATH,
          method: 'POST',
          status: 200,
          body,
          once: true,
        });
  }

  async function proposal() {
    const response = await callTool(server, 'record_meal', meal, token);
    const output = toolResult(response)?.structured as Record<string, unknown> | undefined;
    expect(output, response.rawBody).toMatchObject({ status: 'confirmation_required', meal });
    const confirmation = output?.confirmation_token;
    if (typeof confirmation !== 'string') throw new Error('Missing confirmation');
    keys.push('mcp:confirmation:v1:' + sha256(confirmation));
    return confirmation;
  }

  function confirm(
    confirmation: string,
    target = server,
    args: Record<string, unknown> = meal,
    credential = token
  ) {
    return callTool(
      target,
      'record_meal',
      { ...args, confirmation_token: confirmation },
      credential
    );
  }

  async function adjust(confirmation: string, change: Record<string, unknown>) {
    const redisKey = 'mcp:confirmation:v1:' + sha256(confirmation);
    const stored = await raw.get(redisKey);
    if (!stored) throw new Error('Missing stored confirmation');
    await raw.set(
      redisKey,
      JSON.stringify({ ...(JSON.parse(stored) as Record<string, unknown>), ...change }),
      { KEEPTTL: true }
    );
  }

  function expectRejected(response: McpResponse) {
    expect(
      response.rpc?.error !== undefined ||
        toolResult(response)?.text.includes('"class":"confirmation_required"') === true ||
        toolResult(response)?.isError === true ||
        response.status !== 200,
      response.rawBody
    ).toBe(true);
    expect(toolResult(response)?.structured).not.toMatchObject({ status: 'recorded' });
  }

  function writeReply(once = false, delayMs?: number) {
    mock.route({
      path: '/api/meallog/me',
      method: 'POST',
      status: 201,
      body: {
        success: true,
        data: { ...storedMeal, user_id: '7', idempotency_key_hash: 'hidden' },
      },
      once,
      ...(delayMs === undefined ? {} : { delayMs }),
    });
  }

  describe('record_meal over MCP and shared Redis', () => {
    it('refuses a request budget longer than the configured lease before claiming or writing', async () => {
      active();
      if (configured === undefined) throw new Error('Redis configuration is required');
      const shortLease = await connectConfirmationStore(configured, { leaseMs: 1000 });
      cleanup.push(shortLease.close);
      services.confirmations = shortLease;
      const confirmation = await proposal();
      const refused = await confirm(confirmation);
      expect(toolResult(refused)?.isError).toBe(true);
      expect(toolResult(refused)?.text).toContain('"class":"invalid_input"');
      const stored: unknown = JSON.parse(
        (await raw.get('mcp:confirmation:v1:' + sha256(confirmation))) ?? '{}'
      );
      expect(stored).toMatchObject({ state: 'pending' });
      expect(services.exchangeCredential).not.toHaveBeenCalled();
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    });

    it('lists the scoped tool and runs proposal, confirmation and cross-instance replay with one write', async () => {
      active();
      writeReply();
      const listing = await listTools(server, token);
      expect(listing.rawBody).toContain('record_meal');
      expect(listing.rpc?.result).toMatchObject({ cacheScope: 'private', ttlMs: 0 });
      const confirmation = await proposal();
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
      const saved = await confirm(confirmation);
      expect(toolResult(saved)?.structured, saved.rawBody).toEqual({
        status: 'recorded',
        id: storedMeal.id,
      });
      const cached: unknown = JSON.parse(
        (await raw.get('mcp:confirmation:v1:' + sha256(confirmation))) ?? '{}'
      );
      expect(cached).toMatchObject({
        result: JSON.stringify({ id: storedMeal.id, status: 'recorded' }),
      });
      expect(JSON.stringify(cached)).not.toContain(meal.food_name);
      expect(JSON.stringify(cached)).not.toContain('idempotency_key_hash');
      expect(saved.rawBody).not.toContain(meal.food_name);
      const replay = await confirm(confirmation, otherServer);
      expect(toolResult(replay)?.structured).toEqual(toolResult(saved)?.structured);
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
      expect(services.exchangeCredential).toHaveBeenCalledTimes(1);
    });

    it('rejects changed arguments without consuming the original confirmation', async () => {
      active();
      writeReply();
      const confirmation = await proposal();
      const refused = await confirm(confirmation, otherServer, { ...meal, calories: 201 });
      expectRejected(refused);
      expect(toolResult(refused)?.text).toContain('"class":"confirmation_required"');
      expect(refused.rawBody).not.toContain('confirmation_mismatch');
      expect(refused.rawBody).not.toContain(confirmation);

      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
      expect(toolResult(await confirm(confirmation))?.structured).toMatchObject({
        status: 'recorded',
      });
      expectRejected(await confirm(confirmation, otherServer, { ...meal, sodium: null }));
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
    });

    it.each([
      { field: 'sub', tokenField: 'sub' },
      { field: 'client_id', tokenField: 'clientId' },
      { field: 'grant_id', tokenField: 'grantId' },
    ])(
      'binds confirmations to $field even if the other identity is authorized',
      async ({ field, tokenField }) => {
        active(3);
        active(undefined, { [field]: 'someone-else' });
        const confirmation = await proposal();
        const other = await tokenFor({ [tokenField]: 'someone-else' });
        expectRejected(await confirm(confirmation, otherServer, meal, other));
        expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
      }
    );

    it('refuses a revoked connection on the confirmation request', async () => {
      active(3);
      mock.introspect({ active: false });
      const confirmation = await proposal();
      expect((await confirm(confirmation)).status).toBe(401);
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    });

    it('does not return a cached result after disconnect', async () => {
      active(7);
      mock.introspect({ active: false });
      writeReply();
      const confirmation = await proposal();
      expect(toolResult(await confirm(confirmation))?.structured).toMatchObject({
        status: 'recorded',
      });
      expect((await confirm(confirmation, otherServer)).status).toBe(401);
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
    });

    it('refuses a removed write scope at confirmation and hides the tool on subsequent listing', async () => {
      active(3);
      active(undefined, { scope: 'nutrition:read' });
      const confirmation = await proposal();
      const refused = await confirm(confirmation);
      expect(refused.status).toBe(403);
      expect(refused.challenge).toContain('meallog:write');
      expect((await listTools(server, token)).rawBody).not.toContain('record_meal');
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    });

    it('refuses revocation after request authentication, just before the confirmed write', async () => {
      active(6);
      mock.introspect({ active: false });
      const confirmation = await proposal();
      expectRejected(await confirm(confirmation));
      expect(services.exchangeCredential).toHaveBeenCalledTimes(1);
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    });

    it('makes one write under simultaneous HTTP confirmations on two instances', async () => {
      active();
      writeReply(false, 100);
      const confirmation = await proposal();
      const responses = await Promise.all(
        Array.from({ length: 8 }, (_, index) =>
          confirm(confirmation, index % 2 ? server : otherServer)
        )
      );
      const states = responses.map(
        (response) => (toolResult(response)?.structured as { status?: string } | undefined)?.status
      );
      expect(states).toContain('recorded');
      expect(states.every((state) => state === 'recorded' || state === 'in_progress')).toBe(true);
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
      expect(toolResult(await confirm(confirmation, otherServer))?.structured).toMatchObject({
        status: 'recorded',
      });
    });

    it('recovers a lost write response with the same digest after the lease, then caches it', async () => {
      active();
      // Represents a committed row with a broken response. The second HTTP response returns that
      // row, as Ticket 47 requires. Backend SQL uniqueness is covered in the backend repository.
      mock.route({
        path: '/api/meallog/me',
        method: 'POST',
        status: 201,
        body: 'response-lost',
        once: true,
      });
      writeReply();
      const confirmation = await proposal();
      expectRejected(await confirm(confirmation));
      expect(toolResult(await confirm(confirmation, otherServer))?.structured).toMatchObject({
        status: 'in_progress',
      });
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
      await adjust(confirmation, { lease_until: 0 });
      expect(toolResult(await confirm(confirmation, otherServer))?.structured).toEqual({
        status: 'recorded',
        id: storedMeal.id,
      });
      const calls = mock.callsTo('/api/meallog/me');
      expect(calls).toHaveLength(2);
      for (const call of calls) {
        const headers = Object.fromEntries(
          Object.entries(call.headers).map(([name, value]) => [name.toLowerCase(), value])
        );
        expect(headers['idempotency-key']).toBe(sha256(confirmation));
        expect(call.body).not.toContain(confirmation);
      }
      expect(toolResult(await confirm(confirmation))?.structured).toEqual({
        status: 'recorded',
        id: storedMeal.id,
      });
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(2);
    });

    it('rejects an expired or unknown confirmation without a write', async () => {
      active();
      const confirmation = await proposal();
      await adjust(confirmation, { expires_at: 0 });
      const expired = await confirm(confirmation);
      const unknown = await confirm('z'.repeat(43));
      expectRejected(expired);
      expectRejected(unknown);
      expect(toolResult(expired)?.structured).toMatchObject({
        class: 'confirmation_required',
        confirmation_token: '',
      });
      expect(toolResult(unknown)?.structured).toEqual(toolResult(expired)?.structured);
      expect(expired.rawBody).not.toContain(confirmation);
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    });

    it('does not write or claim a confirmation when durable audit fails', async () => {
      active();
      const confirmation = await proposal();
      services.auditStarted.mockRejectedValue(new Error('audit unavailable'));
      expectRejected(await confirm(confirmation));
      const stored = await raw.get('mcp:confirmation:v1:' + sha256(confirmation));
      expect(JSON.parse(stored ?? '{}')).toMatchObject({ state: 'pending' });
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    });
  });
});
