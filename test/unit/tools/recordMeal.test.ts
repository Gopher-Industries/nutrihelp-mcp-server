import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handler } from '../../../src/tools/recordMeal.ts';
import { ConfirmationError, type ConfirmationStore } from '../../../src/auth/confirmationStore.ts';
import { sha256 } from '../../../src/auth/confirmationArguments.ts';
import { McpError } from '../../../src/errors.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import {
  activeGrant,
  confirmationToken,
  meal,
  mealConfig,
  servicesFor,
  storedMeal,
  verifiedContext,
} from '../../support/recordMeal.ts';

let upstream: UpstreamMock;
beforeEach(() => {
  upstream = installUpstreamMock([]);
});
afterEach(async () => {
  await upstream.restore();
});

function setup() {
  const confirmations = {
    issue: vi
      .fn<ConfirmationStore['issue']>()
      .mockResolvedValue({ confirmationToken, expiresAt: Date.now() + 300000 }),
    execute: vi.fn<ConfirmationStore['execute']>().mockImplementation(async (request, write) => ({
      state: 'done',
      replayed: false,
      result: await write({
        arguments: request.arguments as typeof meal,
        idempotencyKeyHash: sha256(request.confirmationToken),
      }),
    })),
  };
  const services = servicesFor(confirmations);
  const context = verifiedContext();
  return { services, context, call: handler(mealConfig, context, services) };
}

function reply(status = 201, body: object | string = { success: true, data: storedMeal }) {
  upstream.route({ path: '/api/meallog/me', method: 'POST', status, body });
}

describe('record_meal', () => {
  it('previews exact fields, binds every identity and does not write or exchange on proposal', async () => {
    const { call, services } = setup();
    const args = { ...meal, sodium: null, carbs: 0 };
    const response = await call(args);
    expect(response.structuredContent).toMatchObject({
      status: 'confirmation_required',
      meal: args,
      confirmation_token: confirmationToken,
    });
    expect(JSON.stringify(response)).toContain('Porridge');
    expect(services.confirmations.issue).toHaveBeenCalledWith({
      binding: {
        userId: '7',
        assistantId: 'assistant-a',
        connectionId: 'connection-a',
        tool: 'record_meal',
      },
      arguments: args,
    });
    expect(services.exchangeCredential).not.toHaveBeenCalled();
    expect(services.confirmations.execute).not.toHaveBeenCalled();
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it('writes the confirmed snapshot using the unchanged digest and exchanged credential only', async () => {
    const { call, services } = setup();
    reply(201, {
      success: true,
      data: { ...storedMeal, user_id: '7', idempotency_key_hash: 'secret' },
    });
    const response = await call({ ...meal, confirmation_token: confirmationToken });
    expect(response.structuredContent).toEqual({ status: 'recorded', record: storedMeal });
    expect(services.revocation.assertGrantActive).toHaveBeenCalledTimes(3);
    expect(services.auditStarted.mock.invocationCallOrder[0]).toBeLessThan(
      services.exchangeCredential.mock.invocationCallOrder[0] ?? 0
    );
    const writes = upstream.callsTo('/api/meallog/me');
    expect(writes).toHaveLength(1);
    expect(writes[0]).toMatchObject({ method: 'POST', searchParams: {} });
    expect(JSON.parse(writes[0]?.body ?? '{}')).toEqual(meal);
    const headers = Object.fromEntries(
      Object.entries(writes[0]?.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value])
    );
    expect(headers).toMatchObject({
      authorization: 'Bearer exchanged-backend-token',
      'idempotency-key': sha256(confirmationToken),
      'x-correlation-id': 'correlation-test',
    });
    expect(JSON.stringify(writes)).not.toContain(confirmationToken);
    expect(JSON.stringify(writes)).not.toContain('inbound-mcp-token');
    expect(JSON.stringify(response)).not.toContain('idempotency_key_hash');
    expect(JSON.stringify(response)).not.toContain('user_id');
  });

  it('accepts a 200 replay returned by the backend', async () => {
    const { call } = setup();
    reply(200);
    expect(
      (await call({ ...meal, confirmation_token: confirmationToken })).structuredContent
    ).toEqual({ status: 'recorded', record: storedMeal });
  });

  it.each([
    { status: 401, code: -32000 },
    { status: 403, code: -32003 },
  ])('preserves a backend authorization refusal ($status)', async ({ status, code }) => {
    const { call } = setup();
    reply(status, { message: 'private detail' });
    await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code,
    });
  });

  it('returns backend input rejection as a sanitized input error', async () => {
    const { call } = setup();
    reply(400, { message: 'private detail' });
    const response = await call({ ...meal, confirmation_token: confirmationToken });
    expect(response.isError).toBe(true);
    expect(JSON.stringify(response)).not.toContain('private detail');
  });

  it('returns the original completed result without exchange or another write', async () => {
    const { call, services } = setup();
    services.confirmations.execute.mockResolvedValue({
      state: 'done',
      replayed: true,
      result: { status: 'recorded', record: storedMeal },
    });
    expect(
      (await call({ ...meal, confirmation_token: confirmationToken })).structuredContent
    ).toEqual({ status: 'recorded', record: storedMeal });
    expect(services.revocation.assertGrantActive).toHaveBeenCalledTimes(2);
    expect(services.exchangeCredential).not.toHaveBeenCalled();
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it('preserves in_progress so the caller retries the same confirmation', async () => {
    const { call, services } = setup();
    services.confirmations.execute.mockResolvedValue({ state: 'in_progress', retryAfterMs: 2500 });
    expect(
      (await call({ ...meal, confirmation_token: confirmationToken })).structuredContent
    ).toMatchObject({ status: 'in_progress', retry_after_ms: 2500 });
    expect(services.exchangeCredential).not.toHaveBeenCalled();
  });

  it.each([
    { user_id: '99' },
    { userId: 99 },
    { email: 'other@example.test' },
    { ingredients: [] },
    { idempotency_key_hash: 'x' },
    { date: '2026-02-30' },
    { date: '0000-01-01' },
    { time: '25:00' },
    { calories: -1 },
    { calories: '2' },
    { food_name: ' ' },
    { meal_type: '' },
    { confirmation_token: '' },
    { confirmation_token: 'raw' },
    { carbs: Number.MAX_SAFE_INTEGER + 1 },
    { fat: Infinity },
  ])('refuses invalid or identity-bearing input %j before any effect', async (change) => {
    const { call, services } = setup();
    expect((await call({ ...meal, ...change })).isError).toBe(true);
    expect(services.auditStarted).not.toHaveBeenCalled();
    expect(services.confirmations.issue).not.toHaveBeenCalled();
    expect(services.confirmations.execute).not.toHaveBeenCalled();
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it.each(['subject', 'clientId', 'grantId'] as const)(
    'rejects a changed live %s before accessing a stored result',
    async (field) => {
      const { call, services } = setup();
      services.revocation.assertGrantActive.mockResolvedValue({
        ...activeGrant,
        [field]: 'different',
      });
      await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
        code: -32000,
      });
      expect(services.confirmations.execute).not.toHaveBeenCalled();
    }
  );

  it('rejects a revoked grant before reading a completed confirmation', async () => {
    const { call, services, context } = setup();
    services.revocation.assertGrantActive.mockRejectedValue(
      new McpError({
        class: 'unauthorized',
        reason: 'revoked',
        resourceMetadataUrl: context.resourceMetadataUrl,
      })
    );
    await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code: -32000,
    });
    expect(services.confirmations.execute).not.toHaveBeenCalled();
  });

  it('rejects removal of the live write scope even though the JWT still contains it', async () => {
    const { call, services } = setup();
    services.revocation.assertGrantActive.mockResolvedValue({ ...activeGrant, scopes: [] });
    await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code: -32003,
    });
    expect(services.confirmations.execute).not.toHaveBeenCalled();
  });

  it('requires the write scope in the signed token too', async () => {
    const { services } = setup();
    const call = handler(mealConfig, verifiedContext({ tokenScopes: [] }), services);
    await expect(call(meal)).rejects.toMatchObject({ code: -32003 });
    expect(services.confirmations.issue).not.toHaveBeenCalled();
  });

  it.each(['audit', 'exchange'] as const)(
    'checks scope again after %s completes',
    async (stage) => {
      const { call, services } = setup();
      const revoke = () => {
        services.revocation.assertGrantActive.mockResolvedValue({ ...activeGrant, scopes: [] });
      };
      if (stage === 'audit')
        services.auditStarted.mockImplementation(() => {
          revoke();
          return Promise.resolve();
        });
      else
        services.exchangeCredential.mockImplementation(() => {
          revoke();
          return Promise.resolve('backend-token');
        });
      await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
        code: -32003,
      });
      expect(upstream.wireCalls()).toHaveLength(0);
    }
  );

  it.each(['auditStarted', 'exchangeCredential'] as const)(
    'fails closed and sanitizes %s failures',
    async (stage) => {
      const { call, services } = setup();
      services[stage].mockRejectedValue(new Error('private-key raw-token database detail'));
      await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
        code: -32004,
      });
      expect(upstream.wireCalls()).toHaveLength(0);
    }
  );

  it('rejects an inbound token accidentally returned by the exchange adapter', async () => {
    const { call, services, context } = setup();
    services.exchangeCredential.mockResolvedValue(context.token);
    await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code: -32004,
    });
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it.each([{ expiresAt: 0 }, { deadlineAt: 0 }])(
    'fails closed for expired authorization or budget %j',
    async (override) => {
      const { services } = setup();
      await expect(
        handler(mealConfig, verifiedContext(override), services)(meal)
      ).rejects.toThrow();
      expect(services.confirmations.issue).not.toHaveBeenCalled();
    }
  );

  it('fails closed when the deployment adapters have not been supplied', async () => {
    await expect(handler(mealConfig, verifiedContext(), undefined)(meal)).rejects.toMatchObject({
      code: -32004,
    });
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it.each([
    'invalid_confirmation',
    'confirmation_store_unavailable',
    'confirmation_attempt_lost',
  ] as const)('sanitizes confirmation failure %s', async (code) => {
    const { call, services } = setup();
    services.confirmations.execute.mockRejectedValue(new ConfirmationError(code));
    const operation = call({ ...meal, confirmation_token: confirmationToken });
    if (code === 'invalid_confirmation') expect((await operation).isError).toBe(true);
    else await expect(operation).rejects.toMatchObject({ code: -32004 });
    expect(upstream.wireCalls()).toHaveLength(0);
  });

  it('reports a backend key conflict without overwriting or silently issuing a new confirmation', async () => {
    const { call, services } = setup();
    reply(409, { message: 'private detail' });
    expect((await call({ ...meal, confirmation_token: confirmationToken })).isError).toBe(true);
    expect(services.confirmations.issue).not.toHaveBeenCalled();
    expect(upstream.callsTo('/api/meallog/me')).toHaveLength(1);
  });

  it.each([
    { status: 503, body: { message: 'private backend detail' } },
    { status: 201, body: 'not-json' },
    { status: 201, body: { success: true, data: { ...storedMeal, id: 9007199254740992 } } },
    { status: 201, body: { success: true, data: { ...storedMeal, id: 'invalid' } } },
    { status: 201, body: { success: true, data: { ...storedMeal, secret: 'x'.repeat(33000) } } },
  ])('does not expose an unusable backend response ($status)', async ({ status, body }) => {
    const { call } = setup();
    reply(status, body);
    await expect(call({ ...meal, confirmation_token: confirmationToken })).rejects.toMatchObject({
      code: -32004,
    });
    expect(upstream.callsTo('/api/meallog/me')).toHaveLength(1);
  });
});
