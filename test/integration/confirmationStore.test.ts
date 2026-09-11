import { createClient } from '@redis/client';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { connectKeyValue, type KeyValueConnection } from '../../src/upstream/client.ts';
import {
  connectConfirmationStore,
  createConfirmationStore,
  type ConfirmationAction,
  type ConfirmationStore,
  type ConfirmedWrite,
} from '../../src/auth/confirmationStore.ts';
import { sha256, type JsonValue } from '../../src/auth/confirmationArguments.ts';

const action: ConfirmationAction = {
  binding: {
    userId: '7',
    assistantId: 'assistant-a',
    connectionId: 'connection-a',
    tool: 'record_meal',
  },
  arguments: { date: '2026-09-11', meal_type: 'breakfast', food_name: 'Porridge', calories: 200 },
};
const record = { id: '9007199254740993', food_name: 'Porridge', calories: 200 };
const keys: string[] = [];
const cleanup: (() => void)[] = [];
let raw: ReturnType<typeof createClient>;
let connection: KeyValueConnection;
let otherConnection: KeyValueConnection;
let first: ConfirmationStore;
let second: ConfirmationStore;
let url: string;

beforeAll(async () => {
  const configured = process.env.MCP_CONFIRMATION_TEST_REDIS_URL;
  if (!configured)
    throw new Error('Set MCP_CONFIRMATION_TEST_REDIS_URL to a disposable local Redis instance.');
  const parsed = new URL(configured);
  if (!['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname)) {
    throw new Error(
      'These integration tests require local disposable Redis, not a deployed database.'
    );
  }
  url = configured;
  raw = createClient({ url, socket: { reconnectStrategy: false } });
  raw.on('error', () => {
    /* Test operations report their own failures. */
  });
  cleanup.push(() => {
    if (raw.isOpen) raw.destroy();
  });
  await raw.connect();
  connection = await connectKeyValue(url, 1000);
  cleanup.push(connection.close);
  otherConnection = await connectKeyValue(url, 1000);
  cleanup.push(otherConnection.close);
  first = createConfirmationStore(connection);
  second = createConfirmationStore(otherConnection);
});

afterEach(async () => {
  vi.restoreAllMocks();
  // Delete only confirmations issued by this suite. Never FLUSHDB.
  if (keys.length > 0) await raw.del(keys.splice(0));
});

afterAll(() => {
  for (const close of cleanup) close();
});

async function issue(store = first) {
  const proposal = await store.issue(action);
  keys.push('mcp:confirmation:v1:' + sha256(proposal.confirmationToken));
  return proposal;
}

function request(confirmationToken: string) {
  return { ...action, confirmationToken };
}
function key(token: string) {
  return 'mcp:confirmation:v1:' + sha256(token);
}

async function inspect(token: string): Promise<Record<string, unknown>> {
  const value = await raw.get(key(token));
  if (value === null) throw new Error('Expected a stored confirmation');
  return JSON.parse(value) as Record<string, unknown>;
}

/** Simulates elapsed server time without sleeping or substituting any production script. */
async function adjust(token: string, fields: Record<string, unknown>) {
  await raw.set(key(token), JSON.stringify({ ...(await inspect(token)), ...fields }), {
    KEEPTTL: true,
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe('confirmation store with real Redis and independent connections', () => {
  it('records pending state with hashes, a server-clock expiry, and TTL', async () => {
    const proposal = await issue();
    const stored = await inspect(proposal.confirmationToken);
    expect(stored).toMatchObject({ state: 'pending', expires_at: proposal.expiresAt });
    expect(stored.arguments_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(stored.binding_hash).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(stored)).not.toContain(proposal.confirmationToken);
    expect(JSON.stringify(stored)).not.toContain('Porridge');
    expect(await raw.pTTL(key(proposal.confirmationToken))).toBeGreaterThan(0);
    expect(await raw.pTTL(key(proposal.confirmationToken))).toBeLessThanOrEqual(300_000);
  });

  it('returns one completed result across two instances and repeated confirmations', async () => {
    const { confirmationToken } = await issue();
    const write = vi.fn().mockResolvedValue(record);
    expect(await first.execute(request(confirmationToken), write)).toEqual({
      state: 'done',
      result: record,
      replayed: false,
    });
    expect(await second.execute(request(confirmationToken), write)).toEqual({
      state: 'done',
      result: record,
      replayed: true,
    });
    expect(write).toHaveBeenCalledTimes(1);
    expect((await inspect(confirmationToken)).state).toBe('done');
  });

  it('allows only one live claim among concurrent callers', async () => {
    const { confirmationToken } = await issue();
    const gate = deferred<JsonValue>();
    const started = deferred<undefined>();
    const write = vi.fn(() => {
      started.resolve(undefined);
      return gate.promise;
    });
    const original = first.execute(request(confirmationToken), write);
    await started.promise;
    expect((await inspect(confirmationToken)).state).toBe('in_progress');
    const retries = await Promise.all(
      Array.from({ length: 12 }, () => second.execute(request(confirmationToken), write))
    );
    expect(retries.every((result) => result.state === 'in_progress')).toBe(true);
    expect(write).toHaveBeenCalledTimes(1);
    gate.resolve(record);
    await original;
  });

  for (const field of ['userId', 'assistantId', 'connectionId', 'tool'] as const) {
    it(`refuses a different ${field} before and after completion`, async () => {
      const { confirmationToken } = await issue();
      const write = vi.fn().mockResolvedValue(record);
      const changed = {
        ...request(confirmationToken),
        binding: { ...action.binding, [field]: 'different' },
      };
      await expect(second.execute(changed, write)).rejects.toMatchObject({
        code: 'invalid_confirmation',
      });
      expect(write).not.toHaveBeenCalled();
      await first.execute(request(confirmationToken), write);
      await expect(second.execute(changed, write)).rejects.toMatchObject({
        code: 'invalid_confirmation',
      });
      expect(write).toHaveBeenCalledTimes(1);
    });
  }

  it.each([{ calories: 201 }, { calories: '200' }, { food_name: 'Porridge ' }, { sodium: null }])(
    'refuses changed arguments %j without consuming the original',
    async (change) => {
      const { confirmationToken } = await issue();
      const write = vi.fn().mockResolvedValue(record);
      const changed = {
        ...request(confirmationToken),
        arguments: { ...action.arguments, ...change },
      };
      await expect(first.execute(changed, write)).rejects.toMatchObject({
        code: 'invalid_confirmation',
      });
      expect(write).not.toHaveBeenCalled();
      await first.execute(request(confirmationToken), write);
      await expect(first.execute(changed, write)).rejects.toMatchObject({
        code: 'invalid_confirmation',
      });
      expect(write).toHaveBeenCalledTimes(1);
    }
  );

  it('accepts equivalent key order', async () => {
    const { confirmationToken } = await issue();
    const result = await first.execute(
      {
        ...request(confirmationToken),
        arguments: {
          calories: 200,
          food_name: 'Porridge',
          meal_type: 'breakfast',
          date: '2026-09-11',
        },
      },
      vi.fn().mockResolvedValue(record)
    );
    expect(result.state).toBe('done');
  });

  it('refuses unknown and expired values without a write', async () => {
    const { confirmationToken } = await issue();
    const write = vi.fn();
    await expect(first.execute(request('z'.repeat(43)), write)).rejects.toMatchObject({
      code: 'invalid_confirmation',
    });
    await adjust(confirmationToken, { expires_at: 0 });
    await expect(first.execute(request(confirmationToken), write)).rejects.toMatchObject({
      code: 'invalid_confirmation',
    });
    expect(write).not.toHaveBeenCalled();
  });

  it('refuses physically expired records, with no fallback or re-creation', async () => {
    const { confirmationToken } = await issue();
    await raw.pExpire(key(confirmationToken), 1);
    await vi.waitFor(async () => {
      expect(await raw.exists(key(confirmationToken))).toBe(0);
    });
    const write = vi.fn();
    await expect(second.execute(request(confirmationToken), write)).rejects.toMatchObject({
      code: 'invalid_confirmation',
    });
    expect(write).not.toHaveBeenCalled();
    expect(await raw.exists(key(confirmationToken))).toBe(0);
  });

  it('uses Redis time even if the application clock is wrong', async () => {
    const before = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(0);
    const { confirmationToken, expiresAt } = await issue();
    expect(expiresAt).toBeGreaterThan(before);
    await expect(
      first.execute(request(confirmationToken), vi.fn().mockResolvedValue(record))
    ).resolves.toMatchObject({ state: 'done' });
  });

  it('recovers after a backend commit whose response was lost, using the same key', async () => {
    const { confirmationToken } = await issue();
    const rows = new Map<string, JsonValue>();
    let calls = 0;
    // Backend idempotency is Ticket 47's separately tested contract; Redis is real here.
    const backend = vi.fn(({ idempotencyKeyHash }: ConfirmedWrite) => {
      if (!rows.has(idempotencyKeyHash)) rows.set(idempotencyKeyHash, record);
      if (++calls === 1) return Promise.reject(new Error('response lost after commit'));
      return Promise.resolve(rows.get(idempotencyKeyHash) ?? null);
    });
    await expect(first.execute(request(confirmationToken), backend)).rejects.toThrow(
      'response lost'
    );
    expect((await second.execute(request(confirmationToken), backend)).state).toBe('in_progress');
    await adjust(confirmationToken, { lease_until: 0 });
    const recovered = await second.execute(request(confirmationToken), backend);
    expect(recovered).toMatchObject({ state: 'done', result: record });
    expect(rows.size).toBe(1);
    expect(backend).toHaveBeenCalledTimes(2);
    expect(backend.mock.calls.map(([input]) => input.idempotencyKeyHash)).toEqual([
      sha256(confirmationToken),
      sha256(confirmationToken),
    ]);
    expect(await first.execute(request(confirmationToken), backend)).toMatchObject({
      state: 'done',
      replayed: true,
      result: record,
    });
    expect(backend).toHaveBeenCalledTimes(2);
  });

  it('recovers when Redis committed done but its acknowledgement was lost', async () => {
    const { confirmationToken } = await issue();
    let calls = 0;
    const unreliable = createConfirmationStore({
      eval: async (...args) => {
        const reply = await connection.eval(...args);
        if (++calls === 2) throw new Error('lost Redis acknowledgement');
        return reply;
      },
    });
    const write = vi.fn().mockResolvedValue(record);
    await expect(unreliable.execute(request(confirmationToken), write)).rejects.toMatchObject({
      code: 'confirmation_store_unavailable',
    });
    expect(await second.execute(request(confirmationToken), write)).toMatchObject({
      state: 'done',
      result: record,
      replayed: true,
    });
    expect(write).toHaveBeenCalledTimes(1);
  });

  it('fences an old attempt after another instance takes over its expired lease', async () => {
    const { confirmationToken } = await issue();
    const gate = deferred<JsonValue>();
    const started = deferred<undefined>();
    const old = first.execute(request(confirmationToken), () => {
      started.resolve(undefined);
      return gate.promise;
    });
    await started.promise;
    await adjust(confirmationToken, { lease_until: 0 });
    await second.execute(request(confirmationToken), vi.fn().mockResolvedValue(record));
    const rejection = expect(old).rejects.toMatchObject({ code: 'confirmation_attempt_lost' });
    gate.resolve({ id: 'stale result' });
    await rejection;
    expect(await first.execute(request(confirmationToken), vi.fn())).toMatchObject({
      result: record,
      replayed: true,
    });
  });

  it('does not resume an unfinished write after authorization expiry', async () => {
    const { confirmationToken } = await issue();
    await expect(
      first.execute(request(confirmationToken), vi.fn().mockRejectedValue(new Error('timeout')))
    ).rejects.toThrow();
    await adjust(confirmationToken, { expires_at: 0, lease_until: 0 });
    const write = vi.fn();
    await expect(second.execute(request(confirmationToken), write)).rejects.toMatchObject({
      code: 'invalid_confirmation',
    });
    expect(write).not.toHaveBeenCalled();
  });

  it('can retrieve done during result retention after confirmation expiry', async () => {
    const { confirmationToken } = await issue();
    await first.execute(request(confirmationToken), vi.fn().mockResolvedValue(record));
    await adjust(confirmationToken, { expires_at: 0 });
    expect(await second.execute(request(confirmationToken), vi.fn())).toMatchObject({
      state: 'done',
      result: record,
      replayed: true,
    });
    expect(await raw.pTTL(key(confirmationToken))).toBeGreaterThan(86_000_000);
  });

  it('fails closed after losing its Redis connection', async () => {
    const isolated = await connectKeyValue(url, 1000);
    const store = createConfirmationStore(isolated);
    const { confirmationToken } = await issue(store);
    isolated.close();
    const write = vi.fn();
    await expect(store.execute(request(confirmationToken), write)).rejects.toMatchObject({
      code: 'confirmation_store_unavailable',
    });
    await expect(store.issue(action)).rejects.toMatchObject({
      code: 'confirmation_store_unavailable',
    });
    expect(write).not.toHaveBeenCalled();
  });

  it('exposes a usable production connection factory and cleanup', async () => {
    const store = await connectConfirmationStore(url);
    try {
      const { confirmationToken } = await issue(store);
      expect(
        await store.execute(request(confirmationToken), vi.fn().mockResolvedValue(record))
      ).toMatchObject({ state: 'done' });
    } finally {
      store.close();
    }
  });
});
