import { afterAll, afterEach, beforeEach, describe, it } from 'vitest';
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
});
