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
import { contract, handler, inputSchema } from '../../../src/tools/nutritionLookup.ts';

let server: TestServer;
let upstream: UpstreamMock;

beforeEach(async () => {
  upstream = installUpstreamMock([]);
  upstream.route({
    path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
    status: 200,
    body: { success: true, data: [{ category: 'Meat', name: 'chicken breast', calories: 165 }] },
  });

  server = await startTestServer((mcp) => {
    mcp.registerTool(
      'nutrition_lookup',
      { ...contract, inputSchema },
      handler({ nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN })
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
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ data: rows }), { status: 200 })
    );

    const result = await handler({ nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN })({
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
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        JSON.stringify({
          data: [{ id: 1, name: 'food', calories: 1, serving_size: 'x'.repeat(40_000) }],
        }),
        { status: 200 }
      )
    );

    const result = await handler({ nutrihelpApiBaseUrl: NUTRIHELP_API_ORIGIN })({
      food: 'food',
    });

    const text = result.content[0]?.text;
    if (text === undefined) throw new Error('nutrition lookup returned no text content');
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(32 * 1024);
    expect(text).toContain('Response exceeded the 32 KiB limit');
  });
});
