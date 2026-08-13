import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { startTestServer, callTool, closeLocalDispatcher, type TestServer } from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectToolResult } from '../../support/assertions.ts';
import { FOODDATA_SEARCH_PATH, IDENTITY_DENY_LIST, NUTRIHELP_API_ORIGIN } from '../../support/testEnv.ts';
import { registerNutritionLookup } from '../../../src/tools/nutritionLookup.ts';

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
    registerNutritionLookup(mcp, {
      port: 0,
      allowedOriginHostnames: [],
      nutrihelpApiUrl: NUTRIHELP_API_ORIGIN,
    });
  });
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('nutrition_lookup', () => {
  it('returns bounded food data with no identity leak, requiring no token', async () => {
    const response = await callTool(server, 'nutrition_lookup', { query: 'chicken breast' });
    const view = expectToolResult(response, 'nutrition_lookup with no token');

    expect(view.isError).toBe(false);
    expect(view.text.toLowerCase()).toContain('chicken breast');

    for (const field of IDENTITY_DENY_LIST) {
      expect(view.text).not.toContain(`"${field}"`);
    }
  });
});