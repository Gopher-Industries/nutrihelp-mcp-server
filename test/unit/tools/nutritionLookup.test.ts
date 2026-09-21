import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  startTestServer,
  callTool,
  closeLocalDispatcher,
  type TestServer,
} from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectUnauthorizedChallenge, expectWireCalls } from '../../support/assertions.ts';
import {
  ALL_SCOPES,
  CLIENT_ID,
  FOODDATA_SEARCH_PATH,
  GRANT_A,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  NUTRIHELP_API_ORIGIN,
  USER_A,
} from '../../support/testEnv.ts';
import { createTestKeyPair, makeToken } from '../../../scripts/makeToken.ts';
import { CORRELATION_ID_HEADER } from '../../../src/upstream/client.ts';
import { RetryableUpstreamError } from '../../../src/errors.ts';
import { contract, handler, inputSchema } from '../../../src/tools/nutritionLookup.ts';

const REQUEST_DEADLINE_MS = 30_000;

/**
 * The per-dispatch request the registry builds. `remainingBudgetMs` is a FUNCTION on purpose: the
 * handler must read what is left at the moment of the outbound call, not a number captured when it
 * was constructed. There is no `requestDeadlineMs` — the field was deleted so it cannot be read.
 */
const TOOL_REQUEST = {
  nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN,
  remainingBudgetMs: (): number => REQUEST_DEADLINE_MS,
  correlationId: 'nutrition-lookup-suite-correlation-id',
};

let server: TestServer;
let upstream: UpstreamMock;

beforeEach(async () => {
  upstream = installUpstreamMock([]);

  server = await startTestServer((mcp) => {
    mcp.registerTool('nutrition_lookup', { ...contract, inputSchema }, handler(TOOL_REQUEST));
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

    const result = await handler(TOOL_REQUEST)({
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

    const result = await handler(TOOL_REQUEST)({
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

    const result = await handler(TOOL_REQUEST)({
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

    const result = await handler(TOOL_REQUEST)({
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

    await expect(handler(TOOL_REQUEST)({ food: 'apple' })).rejects.toBeInstanceOf(
      RetryableUpstreamError
    );
  });

  it('converts a malformed upstream body into a retryable error', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: 'not-an-array' },
    });

    await expect(handler(TOOL_REQUEST)({ food: 'apple' })).rejects.toBeInstanceOf(
      RetryableUpstreamError
    );
  });

  it('converts malformed nutrition fields into a retryable error before formatting output', async () => {
    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: [{ name: 'apple', calories: '165' }] },
    });

    await expect(handler(TOOL_REQUEST)({ food: 'apple' })).rejects.toBeInstanceOf(
      RetryableUpstreamError
    );
  });
});

/**
 * **ONE IDENTIFIER, TRANSPORT TO THE DATA PATH — asserted on the wire.**
 *
 * `nutrition_lookup` used to pass `correlationId: undefined`, and the egress door answers that by
 * minting one of its own. So a request produced TWO identifiers: the one the transport used for
 * live introspection and its log lines, and a second that reached the backend and joined nothing.
 * Both call sites read as correct on their own — the defect only exists in the relationship, which
 * is why it has to be asserted across the two rather than at either end.
 *
 * Driven through the PRODUCTION registry (`registerRealTools`), because the threading this proves
 * lives in the dispatch wrapper. Reverting it leaves every other suite green.
 */
describe('the correlation identifier, from the transport to the backend', () => {
  it('sends the id the transport minted, not a second one the egress door invented', async () => {
    const key = await createTestKeyPair('mcp-signing-key-1');
    // Its own mock, so the key set this token verifies against is the one being served. The outer
    // fixture publishes no keys, and an unverifiable token stops at 401 before introspection —
    // which would make the "control" below a comparison between two undefineds.
    const mock = installUpstreamMock([key]);
    const token = await makeToken({
      key,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: [...ALL_SCOPES],
      sub: USER_A,
      grantId: GRANT_A,
      clientId: CLIENT_ID,
    });
    mock.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: { data: [{ id: 1, name: 'oats' }] },
    });
    const real = await startTestServer({ registerRealTools: true });

    try {
      await callTool(real, 'nutrition_lookup', { food: 'oats' }, token);

      const minted = real.introspections[0]?.correlationId;
      expect(
        minted,
        'control: the transport minted an id and used it for live introspection, or the comparison below is between two undefineds'
      ).toBeDefined();

      const [call] = expectWireCalls(
        mock.callsTo(FOODDATA_SEARCH_PATH),
        'the tool reached the backend'
      );
      const sent = call?.headers[CORRELATION_ID_HEADER];

      expect(
        sent,
        'the door mints one when handed `undefined`, so an unthreaded handler still puts A header on the wire. Asserting presence would pass on the defect'
      ).toBe(minted);
    } finally {
      await real.close();
      await mock.restore();
    }
  });
});
