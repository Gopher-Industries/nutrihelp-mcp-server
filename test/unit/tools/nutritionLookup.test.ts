import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  startTestServer,
  callTool,
  closeLocalDispatcher,
  type TestServer,
} from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectUnauthorizedChallenge } from '../../support/assertions.ts';
import { FOODDATA_SEARCH_PATH, NUTRIHELP_API_ORIGIN } from '../../support/testEnv.ts';
import { RetryableUpstreamError } from '../../../src/errors.ts';
import { contract, handler, inputSchema } from '../../../src/tools/nutritionLookup.ts';

const REQUEST_DEADLINE_MS = 30_000;

let server: TestServer;
let upstream: UpstreamMock;

beforeEach(async () => {
  upstream = installUpstreamMock([]);

  server = await startTestServer((mcp) => {
    mcp.registerTool(
      'nutrition_lookup',
      { ...contract, inputSchema },
      handler({ nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN, requestDeadlineMs: REQUEST_DEADLINE_MS })
    );
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('nutrition_lookup', () => {
  it('requires the normal MCP authorization challenge', async () => {
    const response = await callTool(server, 'nutrition_lookup', { food: 'chicken breast' });
    expectUnauthorizedChallenge(response, 'nutrition_lookup without a token');
  });

  it('caps candidates and reports how many more matches were omitted', async () => {
    const rows = Array.from({ length: 4 }, (_, id) => ({
      id: id + 1,
      name: `food-${String(id + 1)}`,
    }));
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: rows },
    });

    const result = await handler({
      nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
      requestDeadlineMs: REQUEST_DEADLINE_MS,
    })({
      food: 'food',
    });
    const text = result.content[0]?.text;
    if (text === undefined) throw new Error('nutrition lookup returned no text content');
    const output = JSON.parse(text) as Record<string, unknown>;

    expect(output.candidates).toHaveLength(1);
    expect(output.more_count).toBe(3);
    expect(output.truncated).toBe(true);
  });

  it('keeps a mocked oversized nutrition row under the response-size cap', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: [{ id: 1, name: 'food', calories: 1, serving_size: 'x'.repeat(40_000) }] },
    });

    const result = await handler({
      nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
      requestDeadlineMs: REQUEST_DEADLINE_MS,
    })({
      food: 'food',
    });

    const text = result.content[0]?.text;
    if (text === undefined) throw new Error('nutrition lookup returned no text content');
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(32 * 1024);
    expect(text).toContain('Response exceeded the 32 KiB limit');
  });

  it('projects a valid upstream row into the declared nutrition fields', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: {
        data: [
          {
            id: 7,
            category: 'Fruit',
            name: 'apple',
            calories: 95,
            fat: 0.3,
            carbohydrates: 25,
            protein: 0.5,
            fiber: 4.4,
            vitamin_c: 8.4,
            sodium: 2,
            sugar: 19,
            serving_size: '1 medium apple',
            private_note: 'must not be returned',
          },
        ],
      },
    });

    const result = await handler({
      nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
      requestDeadlineMs: REQUEST_DEADLINE_MS,
    })({
      food: 'apple',
    });
    const output = JSON.parse(result.content[0]?.text ?? '{}') as Record<string, unknown>;
    const item = (output.results as Record<string, unknown>[])[0];

    expect(item).toMatchObject({
      category: 'Fruit',
      name: 'apple',
      calories: 95,
      carbohydrates: 25,
      serving_size: '1 medium apple',
    });
    expect(item).not.toHaveProperty('private_note');
  });

  it('returns the requested item when a matching id is supplied', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: {
        data: [
          { id: 1, name: 'first food' },
          { id: 2, name: 'chosen food' },
        ],
      },
    });

    const result = await handler({
      nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
      requestDeadlineMs: REQUEST_DEADLINE_MS,
    })({
      food: 'food',
      id: 2,
    });
    const output = JSON.parse(result.content[0]?.text ?? '{}') as Record<string, unknown>;
    const items = output.results as Record<string, unknown>[];

    expect(items).toHaveLength(1);
    expect(items[0]?.name).toBe('chosen food');
  });

  it('converts a non-successful upstream response into a retryable error', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 503,
      body: { message: 'temporarily unavailable' },
    });

    await expect(
      handler({
        nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
        requestDeadlineMs: REQUEST_DEADLINE_MS,
      })({ food: 'apple' })
    ).rejects.toBeInstanceOf(RetryableUpstreamError);
  });

  it('converts a malformed upstream body into a retryable error', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: 'not-an-array' },
    });

    await expect(
      handler({
        nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
        requestDeadlineMs: REQUEST_DEADLINE_MS,
      })({ food: 'apple' })
    ).rejects.toBeInstanceOf(RetryableUpstreamError);
  });

  it('converts malformed nutrition fields into a retryable error before formatting output', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: [{ name: 'apple', calories: '165' }] },
    });

    await expect(
      handler({
        nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
        requestDeadlineMs: REQUEST_DEADLINE_MS,
      })({ food: 'apple' })
    ).rejects.toBeInstanceOf(RetryableUpstreamError);
  });
});
