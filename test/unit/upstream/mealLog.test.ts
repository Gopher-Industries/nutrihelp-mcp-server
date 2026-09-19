import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { postMealLog } from '../../../src/upstream/client.ts';
import { meal, mealConfig, storedMeal } from '../../support/recordMeal.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';

let mock: UpstreamMock;
beforeEach(() => {
  mock = installUpstreamMock([]);
});
afterEach(async () => {
  await mock.restore();
});
const request = {
  baseUrl: mealConfig.nutrihelpApiBaseUrl,
  meal,
  credential: 'backend-token',
  idempotencyKeyHash: 'a'.repeat(64),
  correlationId: 'request-id',
  deadlineMs: 1000,
};

describe('confirmed meal write egress', () => {
  it.each([
    { baseUrl: 'http://api.example.test' },
    { baseUrl: 'https://user:password@api.example.test' },
    { baseUrl: 'https://api.example.test?user_id=2' },
    { baseUrl: 'https://api.example.test#fragment' },
    { idempotencyKeyHash: 'A'.repeat(64) },
    { idempotencyKeyHash: 'raw-confirmation' },
    { credential: '' },
    { credential: 'backend\r\nCookie: secret' },
    { deadlineMs: 0 },
    { deadlineMs: 1.5 },
  ])('rejects unsafe write configuration %j before making a request', async (change) => {
    await expect(postMealLog({ ...request, ...change })).rejects.toThrow();
    expect(mock.wireCalls()).toHaveLength(0);
  });

  it('refuses identity fields even if an internal caller bypasses the tool schema', async () => {
    await expect(
      postMealLog({ ...request, meal: { ...meal, ...{ user_id: '99' } } })
    ).rejects.toThrow();
    expect(mock.wireCalls()).toHaveLength(0);
  });

  it('follows no redirect and makes no automatic retry', async () => {
    mock.route({
      path: '/api/meallog/me',
      method: 'POST',
      status: 302,
      body: 'redirect',
      responseHeaders: { location: 'https://elsewhere.example.test/steal' },
    });
    await expect(postMealLog(request)).rejects.toThrow();
    expect(mock.wireCalls()).toHaveLength(1);
  });

  it('pins the write to /api/meallog/me at the configured origin', async () => {
    mock.route({
      path: '/api/meallog/me',
      method: 'POST',
      status: 201,
      body: { success: true, data: storedMeal },
    });
    const response = await postMealLog({
      ...request,
      baseUrl: mealConfig.nutrihelpApiBaseUrl + '/ignored-prefix',
    });
    expect(response.status).toBe(201);
    expect(mock.wireCalls()[0]?.fullUrl).toBe(mealConfig.nutrihelpApiBaseUrl + '/api/meallog/me');
  });
});
