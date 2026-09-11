import { describe, expect, it, vi } from 'vitest';
import {
  createConfirmationStore,
  type ConfirmationAction,
  type ConfirmationStoreOptions,
} from '../../../src/auth/confirmationStore.ts';
import { canonicalJson, sha256 } from '../../../src/auth/confirmationArguments.ts';
import type { KeyValueConnection } from '../../../src/upstream/client.ts';

const action: ConfirmationAction = {
  binding: {
    userId: '7',
    assistantId: 'assistant-a',
    connectionId: 'connection-a',
    tool: 'record_meal',
  },
  arguments: { date: '2026-09-11', food_name: 'Porridge', meal_type: 'breakfast', calories: 200 },
};
const token = 'a'.repeat(43);
const record = { id: '9007199254740993', ...action.arguments };

function setup() {
  // Reply fixtures exercise the TS protocol. Real Lua state transitions are tested against Redis.
  const evaluate = vi.fn<KeyValueConnection['eval']>();
  return { evaluate, store: createConfirmationStore({ eval: evaluate }) };
}

describe('confirmation store protocol', () => {
  it('issues an unpredictable value but persists only hashes', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(['issued', '1800000000000']);
    const one = await store.issue(action);
    const two = await store.issue(action);
    expect(one.confirmationToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(one.confirmationToken).not.toBe(two.confirmationToken);
    expect(one.expiresAt).toBe(1800000000000);
    expect(evaluate.mock.calls[0]?.[1]).toEqual([
      'mcp:confirmation:v1:' + sha256(one.confirmationToken),
    ]);
    expect(evaluate.mock.calls[0]?.[2]?.[1]).toBe(sha256(canonicalJson(action.arguments)));
    const stored = JSON.stringify(evaluate.mock.calls);
    expect(stored).not.toContain(one.confirmationToken);
    expect(stored).not.toContain('Porridge');
    expect(stored).not.toContain('assistant-a');
  });

  it('binds every identity component without ambiguous concatenation', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(['issued', '1800000000000']);
    await store.issue(action);
    for (const field of ['userId', 'assistantId', 'connectionId', 'tool'] as const) {
      await store.issue({ ...action, binding: { ...action.binding, [field]: 'different' } });
    }
    const hashes = evaluate.mock.calls.map((call) => call[2][0]);
    expect(new Set(hashes).size).toBe(5);
  });

  it('gives the writer the matching snapshot and a single SHA-256 for Ticket 47', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValueOnce(['claimed']).mockResolvedValueOnce(['completed']);
    const write = vi.fn().mockResolvedValue(record);
    const result = await store.execute({ ...action, confirmationToken: token }, write);
    expect(write).toHaveBeenCalledWith({
      arguments: action.arguments,
      idempotencyKeyHash: sha256(token),
    });
    expect(result).toEqual({ state: 'done', replayed: false, result: record });
    expect(JSON.stringify(evaluate.mock.calls)).not.toContain(token);
    expect(JSON.stringify(write.mock.calls)).not.toContain(token);
  });

  it('takes the snapshot before awaiting storage', async () => {
    const { store, evaluate } = setup();
    const args = { ...action.arguments, food_name: 'Porridge', nested: { amount: 1 } };
    evaluate
      .mockImplementationOnce(() => {
        args.food_name = 'Altered';
        args.nested.amount = 99;
        return Promise.resolve(['claimed']);
      })
      .mockResolvedValueOnce(['completed']);
    const write = vi.fn().mockResolvedValue(record);
    await store.execute({ ...action, arguments: args, confirmationToken: token }, write);
    expect(write.mock.calls[0]?.[0]).toMatchObject({
      arguments: { food_name: 'Porridge', nested: { amount: 1 } },
    });
  });

  it('returns the saved result without invoking the writer', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(['done', JSON.stringify(record)]);
    const write = vi.fn();
    expect(await store.execute({ ...action, confirmationToken: token }, write)).toEqual({
      state: 'done',
      result: record,
      replayed: true,
    });
    expect(write).not.toHaveBeenCalled();
  });

  it('reports a held lease without issuing a concurrent write', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(['in_progress', '500']);
    const write = vi.fn();
    expect(await store.execute({ ...action, confirmationToken: token }, write)).toEqual({
      state: 'in_progress',
      retryAfterMs: 500,
    });
    expect(write).not.toHaveBeenCalled();
  });

  it.each(['', 'short', 'a'.repeat(44), '/'.repeat(43)])(
    'rejects malformed tokens before storage',
    async (confirmationToken) => {
      const { store, evaluate } = setup();
      await expect(store.execute({ ...action, confirmationToken }, vi.fn())).rejects.toMatchObject({
        code: 'invalid_confirmation',
      });
      expect(evaluate).not.toHaveBeenCalled();
    }
  );

  it.each(
    [
      ['invalid'],
      ['unknown'],
      ['done', 'not json'],
      ['done'],
      ['in_progress', '-1'],
      ['in_progress', 'nonsense'],
    ].map((reply) => ({ reply }))
  )('fails closed on a refused or malformed claim $reply', async ({ reply }) => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(reply);
    const write = vi.fn();
    await expect(store.execute({ ...action, confirmationToken: token }, write)).rejects.toThrow();
    expect(write).not.toHaveBeenCalled();
  });

  it.each(
    [null, ['issued', 'nan'], ['issued', '-1'], ['collision'], [123], []].map((reply) => ({
      reply,
    }))
  )('fails closed on an unusable issue response %j', async ({ reply }) => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(reply);
    await expect(store.issue(action)).rejects.toMatchObject({
      code: 'confirmation_store_unavailable',
    });
  });

  it('sanitizes storage failures and never invokes the writer during an outage', async () => {
    const { store, evaluate } = setup();
    evaluate.mockRejectedValue(new Error('redis://secret:password@host/' + token));
    const write = vi.fn();
    const error: unknown = await store
      .execute({ ...action, confirmationToken: token }, write)
      .catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'confirmation_store_unavailable' });
    expect(error).not.toHaveProperty('cause');
    expect(String(error)).not.toContain('password');
    expect(String(error)).not.toContain(token);
    expect(write).not.toHaveBeenCalled();
  });

  it('does not reset or complete an uncertain backend write', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(['claimed']);
    await expect(
      store.execute(
        { ...action, confirmationToken: token },
        vi.fn().mockRejectedValue(new Error('timeout'))
      )
    ).rejects.toThrow('timeout');
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it('reports a lost lease instead of claiming an uncached success', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValueOnce(['claimed']).mockResolvedValueOnce(['lost']);
    await expect(
      store.execute({ ...action, confirmationToken: token }, vi.fn().mockResolvedValue(record))
    ).rejects.toMatchObject({ code: 'confirmation_attempt_lost' });
  });

  it('refuses oversized results while preserving the pending write recovery path', async () => {
    const { store, evaluate } = setup();
    evaluate.mockResolvedValue(['claimed']);
    await expect(
      store.execute(
        { ...action, confirmationToken: token },
        vi.fn().mockResolvedValue('x'.repeat(70_000))
      )
    ).rejects.toThrow(TypeError);
    expect(evaluate).toHaveBeenCalledTimes(1);
  });

  it.each([
    { lifetimeMs: 0 },
    { lifetimeMs: 900_001 },
    { lifetimeMs: NaN },
    { leaseMs: 400_000 },
    { leaseMs: 1.5 },
    { commandTimeoutMs: -1 },
    { resultTtlMs: 1 },
    { resultTtlMs: Infinity },
  ] satisfies ConfirmationStoreOptions[])('rejects unsafe durations %j', (options) => {
    expect(() => createConfirmationStore({ eval: vi.fn() }, options)).toThrow(TypeError);
  });

  it.each(['', ' ', 'x'.repeat(513)])(
    'requires a complete verified binding',
    async (assistantId) => {
      const { store, evaluate } = setup();
      await expect(
        store.issue({ ...action, binding: { ...action.binding, assistantId } })
      ).rejects.toThrow(TypeError);
      expect(evaluate).not.toHaveBeenCalled();
    }
  );
});
