/** Real transport, JWT validation, live introspection/exchange, shared Redis and Lua.
 * Only authorization-server/backend HTTP are intercepted. No durable audit claim is made.
 */
import { createClient } from '@redis/client';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { connectConfirmationStore } from '../../src/server.ts';
import { sha256, type ConfirmationStore } from '../../src/consent/confirmation.ts';
import { missingScopeFor } from '../../src/auth/scopes.ts';
import type { ConfirmationAnomalyEvent } from '../../src/tools/registry.ts';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../scripts/makeToken.ts';
import { installUpstreamMock, type UpstreamMock } from '../support/upstreamMock.ts';
import {
  callTool,
  closeLocalDispatcher,
  listTools,
  startTestServer,
  toolResult,
  type TestServer,
} from '../support/mcpClient.ts';
import {
  AUTH_SERVER_ORIGIN,
  INTROSPECTION_PATH,
  TOKEN_EXCHANGE_PATH,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  SCOPES,
  USER_A,
  CLIENT_ID,
  GRANT_A,
} from '../support/testEnv.ts';
import { meal, storedMeal } from '../support/recordMeal.ts';

const configured = process.env.MCP_CONFIRMATION_TEST_REDIS_URL;
if (configured === undefined)
  console.warn(
    'SKIP record_meal Redis integration: MCP_CONFIRMATION_TEST_REDIS_URL is absent. CI supplies disposable Redis.'
  );
let key: TestKeyPair;
let raw: ReturnType<typeof createClient>;
let first: Awaited<ReturnType<typeof connectConfirmationStore>>;
let second: Awaited<ReturnType<typeof connectConfirmationStore>>;
let mock: UpstreamMock;
let server: TestServer;
let otherServer: TestServer;
let token: string;
const keys: string[] = [];
const anomalies: ConfirmationAnomalyEvent[] = [];
const closes: (() => void)[] = [];
const credential = 'exchanged-meal-backend-credential';

function tracked(store: ConfirmationStore): ConfirmationStore {
  return {
    issue: async (action) => {
      const proposal = await store.issue(action);
      keys.push('mcp:confirmation:v1:' + sha256(proposal.confirmationToken));
      return proposal;
    },
    execute: (action, write) => store.execute(action, write),
  };
}

describe.skipIf(configured === undefined)('record_meal Redis gate', () => {
  beforeAll(async () => {
    if (
      !configured ||
      !['localhost', '127.0.0.1', '[::1]'].includes(new URL(configured).hostname)
    ) {
      throw new Error('Set MCP_CONFIRMATION_TEST_REDIS_URL to disposable LOCAL Redis.');
    }
    raw = createClient({ url: configured, socket: { reconnectStrategy: false } });
    raw.on('error', () => undefined);
    closes.push(() => {
      if (raw.isOpen) raw.destroy();
    });
    await raw.connect();
    first = await connectConfirmationStore(configured, { leaseMs: 60000 });
    closes.push(first.close);
    second = await connectConfirmationStore(configured, { leaseMs: 60000 });
    closes.push(second.close);
    key = await createTestKeyPair('record-meal-integration');
  });
  beforeEach(async () => {
    anomalies.length = 0;
    mock = installUpstreamMock([key]);
    mock.exchange({
      access_token: credential,
      token_type: 'Bearer',
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      expires_in: 120,
    });
    const options = {
      registerRealTools: true,
      missingScopeFor,
      revocation: 'live' as const,
      credentials: 'live' as const,
      logConfirmationAnomaly: (event: ConfirmationAnomalyEvent) => {
        anomalies.push(event);
      },
    };
    server = await startTestServer({ ...options, confirmations: tracked(first) });
    otherServer = await startTestServer({ ...options, confirmations: tracked(second) });
    token = await tokenFor();
  });
  afterEach(async () => {
    await server.close();
    await otherServer.close();
    await mock.restore();
    if (keys.length) await raw.del(keys.splice(0));
  });
  afterAll(async () => {
    for (const close of closes) close();
    await closeLocalDispatcher();
  });
  function tokenFor(
    change: { sub?: string; clientId?: string; grantId?: string; scopes?: string[] } = {}
  ) {
    return makeToken({
      key,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      sub: USER_A,
      clientId: CLIENT_ID,
      grantId: GRANT_A,
      scopes: [SCOPES.meallogWrite],
      ...change,
    });
  }
  function active(times?: number, change: Record<string, unknown> = {}) {
    const body = {
      active: true,
      sub: USER_A,
      client_id: CLIENT_ID,
      grant_id: GRANT_A,
      scope: SCOPES.meallogWrite,
      ...change,
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
  async function proposal(target = server) {
    const response = await callTool(target, 'record_meal', meal, token);
    const output = toolResult(response)?.structured as Record<string, unknown> | undefined;
    expect(output, response.rawBody).toMatchObject({ status: 'confirmation_required' });
    expect(output?.summary).toContain(
      JSON.stringify({
        date: meal.date,
        meal_type: meal.meal_type,
        food_name: meal.food_name,
        calories: meal.calories,
      })
    );
    if (typeof output?.confirmation_token !== 'string') throw new Error('Missing confirmation');
    return output.confirmation_token;
  }
  function confirm(
    confirmation: string,
    target = server,
    args: Record<string, unknown> = meal,
    bearer = token
  ) {
    return callTool(target, 'record_meal', { ...args, confirmation_token: confirmation }, bearer);
  }
  async function adjust(confirmation: string, change: Record<string, unknown>) {
    const redisKey = 'mcp:confirmation:v1:' + sha256(confirmation);
    const value = await raw.get(redisKey);
    if (!value) throw new Error('Missing stored confirmation');
    await raw.set(
      redisKey,
      JSON.stringify({ ...(JSON.parse(value) as Record<string, unknown>), ...change }),
      { KEEPTTL: true }
    );
  }
  function writeReply(delayMs?: number) {
    mock.route({
      path: '/api/meallog/me',
      method: 'POST',
      status: 201,
      body: {
        success: true,
        data: { ...storedMeal, user_id: 'secret', idempotency_key_hash: 'hidden' },
      },
      ...(delayMs === undefined ? {} : { delayMs }),
    });
  }
  it('lists, previews, writes and replays across instances; each request introspects once', async () => {
    active();
    writeReply();
    expect((await listTools(server, token)).rawBody).toContain('record_meal');
    const confirmation = await proposal();
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    const saved = await confirm(confirmation);
    expect(toolResult(saved)?.structured, saved.rawBody).toEqual({
      status: 'recorded',
      id: storedMeal.id,
    });
    expect(toolResult(await confirm(confirmation, otherServer))?.structured).toEqual(
      toolResult(saved)?.structured
    );
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
    expect(mock.callsTo(INTROSPECTION_PATH)).toHaveLength(4);
    expect(mock.callsTo(TOKEN_EXCHANGE_PATH).length).toBeGreaterThan(0);
    const write = mock.callsTo('/api/meallog/me')[0];
    expect(write?.headers).toMatchObject({
      authorization: 'Bearer ' + credential,
      'idempotency-key': sha256(confirmation),
    });
    expect(JSON.stringify(write)).not.toContain(token);
    expect(JSON.stringify(write)).not.toContain(confirmation);
    const cached: unknown = JSON.parse(
      (await raw.get('mcp:confirmation:v1:' + sha256(confirmation))) ?? '{}'
    );
    expect(cached).toMatchObject({
      result: JSON.stringify({ id: storedMeal.id, status: 'recorded' }),
    });
    expect(JSON.stringify(cached)).not.toContain(meal.food_name);
    expect(saved.rawBody).not.toContain('secret');
  });
  it('logs one mismatch, issues a replacement, and preserves the original confirmation', async () => {
    active();
    writeReply();
    const confirmation = await proposal();
    const mismatch = await confirm(confirmation, otherServer, { ...meal, calories: 999 });
    const pending = toolResult(mismatch)?.structured as Record<string, unknown>;
    expect(pending).toMatchObject({ status: 'confirmation_required' });
    expect(pending.confirmation_token).not.toBe(confirmation);
    expect(mismatch.rawBody).not.toContain('confirmation_mismatch');
    expect(anomalies).toEqual([
      {
        detailCode: 'confirmation_mismatch',
        tool: 'record_meal',
        grantId: GRANT_A,
        correlationId: expect.any(String) as unknown,
      },
    ]);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    expect(toolResult(await confirm(confirmation))?.structured).toMatchObject({
      status: 'recorded',
    });
  });
  it.each([
    { field: 'sub', tokenField: 'sub' },
    { field: 'client_id', tokenField: 'clientId' },
    { field: 'grant_id', tokenField: 'grantId' },
  ])('binds confirmations to live $field', async ({ field, tokenField }) => {
    active(1);
    active(undefined, { [field]: 'someone-else' });
    const confirmation = await proposal();
    const other = await tokenFor({ [tokenField]: 'someone-else' });
    expect(
      toolResult(await confirm(confirmation, otherServer, meal, other))?.structured
    ).toMatchObject({ status: 'confirmation_required' });
    expect(anomalies).toHaveLength(1);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
  });
  it('refuses a revoked confirmation', async () => {
    active(1);
    mock.introspect({ active: false });
    const confirmation = await proposal();
    expect((await confirm(confirmation)).status).toBe(401);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
  });
  it('does not replay a cached result after revocation', async () => {
    active(2);
    mock.introspect({ active: false });
    writeReply();
    const confirmation = await proposal();
    expect(toolResult(await confirm(confirmation))?.structured).toMatchObject({
      status: 'recorded',
    });
    expect((await confirm(confirmation, otherServer)).status).toBe(401);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
  });
  it('refuses removed scope on every confirmation before the store or write', async () => {
    active(1);
    active(undefined, { scope: 'nutrition:read' });
    const confirmation = await proposal();
    expect((await confirm(confirmation)).status).toBe(403);
    expect((await confirm(confirmation, otherServer)).status).toBe(403);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
  });
  it('writes once under concurrent confirmations on two instances', async () => {
    active();
    writeReply(100);
    const confirmation = await proposal();
    const responses = await Promise.all(
      Array.from({ length: 8 }, (_, i) => confirm(confirmation, i % 2 ? server : otherServer))
    );
    const states = responses.map(
      (r) => (toolResult(r)?.structured as { status?: string } | undefined)?.status
    );
    expect(states).toContain('recorded');
    expect(states.every((s) => s === 'recorded' || s === 'in_progress')).toBe(true);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
  });
  it('retries a lost response with the same digest after lease expiry and caches the receipt', async () => {
    active();
    mock.route({
      path: '/api/meallog/me',
      method: 'POST',
      status: 201,
      body: 'lost-response',
      once: true,
    });
    writeReply();
    const confirmation = await proposal();
    const lost = await confirm(confirmation);
    expect(toolResult(lost)?.isError, lost.rawBody).toBe(true);
    expect(toolResult(await confirm(confirmation, otherServer))?.structured).toMatchObject({
      status: 'in_progress',
    });
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(1);
    await adjust(confirmation, { lease_until: 0 });
    expect(toolResult(await confirm(confirmation, otherServer))?.structured).toEqual({
      status: 'recorded',
      id: storedMeal.id,
    });
    for (const write of mock.callsTo('/api/meallog/me'))
      expect(write.headers['idempotency-key']).toBe(sha256(confirmation));
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(2);
    await confirm(confirmation);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(2);
  });
  it('returns fresh nonempty confirmations for expiry/unknown/mismatch, without revealing the reason', async () => {
    active();
    const confirmation = await proposal();
    await adjust(confirmation, { expires_at: 0 });
    const expired = toolResult(await confirm(confirmation))?.structured as Record<string, unknown>;
    const unknown = toolResult(await confirm('z'.repeat(43)))?.structured as Record<
      string,
      unknown
    >;
    const mismatched = toolResult(await confirm(confirmation, server, { ...meal, calories: 999 }))
      ?.structured as Record<string, unknown>;
    for (const result of [expired, unknown, mismatched]) {
      expect(result).toMatchObject({
        status: 'confirmation_required',
        confirmation_token: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) as unknown,
      });
      expect(result.confirmation_token).not.toBe(confirmation);
      expect(result).not.toHaveProperty('detailCode');
    }
    const { confirmation_token: expiredToken, ...expiredShape } = expired;
    const { confirmation_token: unknownToken, ...unknownShape } = unknown;
    expect(expiredToken).not.toBe(unknownToken);
    expect(expiredShape).toEqual(unknownShape);
    expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
  });
  it('rejects a lease shorter than the HTTP budget before claiming', async () => {
    active();
    if (!configured) throw new Error('Missing Redis URL');
    const short = await connectConfirmationStore(configured, { leaseMs: 1000 });
    const shortServer = await startTestServer({
      registerRealTools: true,
      missingScopeFor,
      confirmations: tracked(short),
      revocation: 'live',
      credentials: 'live',
    });
    try {
      const confirmation = await proposal(shortServer);
      const response = await confirm(confirmation, shortServer);
      expect(toolResult(response)?.isError).toBe(true);
      expect(
        JSON.parse((await raw.get('mcp:confirmation:v1:' + sha256(confirmation))) ?? '{}')
      ).toMatchObject({ state: 'pending' });
      expect(mock.callsTo('/api/meallog/me')).toHaveLength(0);
    } finally {
      await shortServer.close();
      short.close();
    }
  });
});
