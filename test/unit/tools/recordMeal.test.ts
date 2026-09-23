import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConfirmationError } from '../../../src/errors.ts';
import { sha256 } from '../../../src/consent/confirmation.ts';
import { inputSchema, MEAL_FIELDS, descriptor, handler } from '../../../src/tools/recordMeal.ts';
import { isIdentityField } from '../../../src/upstream/client.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { setupMeal, meal, storedMeal, confirmationToken } from '../../support/recordMeal.ts';

let upstream: UpstreamMock;
beforeEach(() => {
  upstream = installUpstreamMock([]);
});
afterEach(async () => {
  vi.restoreAllMocks();
  await upstream.restore();
});
function reply(status = 201, body: object | string = { success: true, data: storedMeal }) {
  upstream.route({ path: '/api/meallog/me', method: 'POST', status, body });
}

describe('record_meal on the central dispatch path', () => {
  it('declares scope, credentialed backing, named schema and non-idempotent proposals', () => {
    expect(descriptor).toMatchObject({
      name: 'record_meal',
      scope: 'meallog:write',
      backing: 'credentialed',
    });
    expect(descriptor.inputSchema).toBe(inputSchema);
    expect(descriptor.contract.annotations.idempotentHint).toBe(false);
    expect(MEAL_FIELDS.some(isIdentityField)).toBe(false);
  });

  it('previews exact arguments and binds the live grant, never AuthInfo identity', async () => {
    const h = setupMeal();
    const response = await h.call(meal);
    expect(response.structuredContent).toMatchObject({
      status: 'confirmation_required',
      confirmation_token: confirmationToken,
    });
    expect(response.structuredContent).toMatchObject({
      summary: expect.stringContaining(
        JSON.stringify({
          date: meal.date,
          meal_type: meal.meal_type,
          food_name: meal.food_name,
          calories: meal.calories,
        })
      ) as unknown,
    });
    expect(h.confirmations.issue).toHaveBeenCalledWith({
      binding: {
        userId: '7',
        assistantId: 'assistant-a',
        connectionId: 'connection-a',
        tool: 'record_meal',
      },
      arguments: meal,
    });
    expect(h.confirmations.execute).not.toHaveBeenCalled();
    expect(upstream.wireCalls()).toHaveLength(0);
    expect(h.config.auditEnqueue).toHaveBeenCalledTimes(1);
    expect(h.credentialFor).toHaveBeenCalledTimes(1);
  });

  it.each([200, 201])(
    'writes with the unchanged digest and exchanged credential (%s)',
    async (status) => {
      reply(status, { success: true, data: { ...storedMeal, user_id: 'hidden' } });
      const h = setupMeal();
      const result = await h.call({ ...meal, confirmation_token: confirmationToken });
      expect(result.structuredContent).toEqual({ status: 'recorded', id: storedMeal.id });
      const writes = upstream.callsTo('/api/meallog/me');
      expect(writes).toHaveLength(1);
      expect(JSON.parse(writes[0]?.body ?? '{}')).toEqual(meal);
      expect(writes[0]?.headers).toMatchObject({
        authorization: 'Bearer exchanged-backend-token',
        'idempotency-key': sha256(confirmationToken),
        'x-correlation-id': 'correlation-test',
      });
      expect(JSON.stringify(writes)).not.toContain('inbound-mcp-token');
      expect(JSON.stringify(writes)).not.toContain(confirmationToken);
    }
  );

  it('projects cached results again, including legacy full records', async () => {
    const h = setupMeal();
    const legacy = { ...storedMeal, status: 'recorded', user_id: 'secret' };
    h.confirmations.execute.mockResolvedValue({
      state: 'done',
      replayed: true,
      result: legacy,
    });
    const result = await h.call({ ...meal, confirmation_token: confirmationToken });
    expect(result.structuredContent).toEqual({ status: 'recorded', id: storedMeal.id });
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it('keeps in-progress retries on the same confirmation', async () => {
    const h = setupMeal();
    h.confirmations.execute.mockResolvedValue({ state: 'in_progress', retryAfterMs: 250 });
    expect(
      (await h.call({ ...meal, confirmation_token: confirmationToken })).structuredContent
    ).toMatchObject({ status: 'in_progress', retry_after_ms: 250 });
  });

  it.each(['invalid_confirmation', 'confirmation_mismatch'] as const)(
    'returns a fresh pending action for %s',
    async (code) => {
      const h = setupMeal();
      h.confirmations.issue.mockResolvedValue({
        confirmationToken: 'b'.repeat(43),
        expiresAt: 1790000000000,
      });
      h.confirmations.execute.mockRejectedValue(new ConfirmationError(code));
      const response = await h.call({ ...meal, confirmation_token: confirmationToken });
      expect(response.structuredContent).toMatchObject({
        status: 'confirmation_required',
        confirmation_token: 'b'.repeat(43),
      });
      expect(JSON.stringify(response)).not.toContain(code);
      expect(JSON.stringify(response)).not.toContain(confirmationToken);
      expect(upstream.wireCalls()).toHaveLength(0);
    }
  );

  it('logs exactly one narrow mismatch anomaly and exposes the same payload as expiry', async () => {
    const mismatch = setupMeal();
    mismatch.confirmations.execute.mockRejectedValue(
      new ConfirmationError('confirmation_mismatch')
    );
    const expired = setupMeal();
    expired.confirmations.execute.mockRejectedValue(new ConfirmationError('invalid_confirmation'));
    const args = { ...meal, confirmation_token: 'c'.repeat(43) };
    expect(await mismatch.call(args)).toEqual(await expired.call(args));
    expect(mismatch.anomalies).toEqual([
      {
        detailCode: 'confirmation_mismatch',
        tool: 'record_meal',
        grantId: 'connection-a',
        correlationId: 'correlation-test',
      },
    ]);
    expect(expired.anomalies).toHaveLength(0);
    expect(JSON.stringify(mismatch.anomalies)).not.toContain('token');
  });

  it('does not expose logger failures', async () => {
    const h = setupMeal();
    vi.spyOn(h.config, 'logConfirmationAnomaly').mockImplementation(() => {
      throw new Error('private-log');
    });
    h.confirmations.execute.mockRejectedValue(new ConfirmationError('confirmation_mismatch'));
    expect(
      (await h.call({ ...meal, confirmation_token: confirmationToken })).structuredContent
    ).toMatchObject({ status: 'confirmation_required' });
  });

  it.each([401, 403, 500, 503, 429, 202])(
    'maps backend %s to upstream_failure without leaking its body',
    async (status) => {
      reply(status, 'private-backend-detail');
      const h = setupMeal();
      await expect(
        h.call({ ...meal, confirmation_token: confirmationToken })
      ).rejects.toMatchObject({ code: -32004 });
    }
  );

  it('sanitizes backend input rejection', async () => {
    reply(400, 'private detail');
    const h = setupMeal();
    const response = await h.call({ ...meal, confirmation_token: confirmationToken });
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response)).not.toContain('private detail');
  });

  it('logs backend conflict as the same mismatch anomaly', async () => {
    reply(409, 'private detail');
    const h = setupMeal();
    expect(
      (await h.call({ ...meal, confirmation_token: confirmationToken })).structuredContent
    ).toMatchObject({ status: 'confirmation_required' });
    expect(h.anomalies).toHaveLength(1);
  });

  it.each([
    { user_id: '99' },
    { email: 'other@example.test' },
    { idempotency_key_hash: 'x' },
    { date: '2026-02-30' },
    { date: '0000-01-01' },
    { date: 'invalid' },
    { time: '25:00' },
    { calories: -1 },
    { calories: '2' },
    { food_name: ' ' },
    { meal_type: '' },
    { confirmation_token: '' },
    { confirmation_token: 'raw' },
    { fat: Infinity },
    { carbs: Number.MAX_SAFE_INTEGER + 1 },
  ])('refuses invalid input %j before confirmation or write', async (change) => {
    const h = setupMeal();
    expect((await h.call({ ...meal, ...change })).isError).toBe(true);
    expect(h.confirmations.issue).not.toHaveBeenCalled();
    expect(h.confirmations.execute).not.toHaveBeenCalled();
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it.each([
    {},
    { success: false },
    { success: true, data: { ...storedMeal, id: '0' } },
    { success: true, data: { ...storedMeal, id: '9223372036854775808' } },
  ])('rejects malformed success %j', async (body) => {
    reply(201, body);
    const h = setupMeal();
    await expect(h.call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code: -32004,
    });
  });

  it('refuses inbound credentials even if the exchange provider returns them', async () => {
    const h = setupMeal();
    h.credentialFor.mockResolvedValue({
      accessToken: 'inbound-mcp-token',
      grantId: 'connection-a',
      usableUntilMs: Date.now() + 60000,
    });
    await expect(h.call(meal)).rejects.toMatchObject({ class: 'upstream_failure' });
    expect(h.confirmations.issue).not.toHaveBeenCalled();
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it('does not extend the post-claim budget', async () => {
    const h = setupMeal();
    h.confirmations.execute.mockImplementation(async (_request, write) => {
      await write({
        arguments: meal,
        idempotencyKeyHash: sha256(confirmationToken),
        deadlineMs: 1,
      });
      return { state: 'done', replayed: false, result: { id: storedMeal.id, status: 'recorded' } };
    });
    upstream.route({
      path: '/api/meallog/me',
      method: 'POST',
      status: 201,
      body: { success: true, data: storedMeal },
      delayMs: 50,
    });
    await expect(h.call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code: -32004,
    });
  });

  it('refuses a missing credential at the handler boundary', async () => {
    const h = setupMeal();
    const call = handler({
      ...mealConfigForTest(),
      confirmations: h.confirmations,
      caller: { subject: '7', clientId: 'assistant-a', grantId: 'connection-a' },
      credential: undefined,
      remainingBudgetMs: () => 30000,
      correlationId: 'test',
    });
    await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });
});
function mealConfigForTest() {
  return { nutrihelpApiBaseUrl: 'https://api.nutrihelp.test' };
}
