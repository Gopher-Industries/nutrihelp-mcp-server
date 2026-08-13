import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { request, Agent } from 'undici';
import {
  McpServer,
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from '@modelcontextprotocol/server';
import { createHttpApp } from '../../src/transport/http.ts';
import { registerNutritionLookup } from '../../src/tools/nutritionLookup.ts';
import {
  ALLOWED_ORIGIN,
  ALLOWED_ORIGIN_HOSTNAMES,
  IDENTITY_DENY_LIST,
  NUTRIHELP_API_ORIGIN,
} from '../support/testEnv.ts';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const PROTOCOL_REVISION = '2026-07-28';
const localDispatcher = new Agent({ keepAliveTimeout: 10, keepAliveMaxTimeout: 10 });

const REQUEST_ENVELOPE = {
  [PROTOCOL_VERSION_META_KEY]: PROTOCOL_REVISION,
  [CLIENT_INFO_META_KEY]: { name: 'nutrihelp-conformance', version: '1.0.0' },
  [CLIENT_CAPABILITIES_META_KEY]: {},
};

interface TestHarness {
  readonly baseUrl: string;
  close(): Promise<void>;
}

async function startTestServer(): Promise<TestHarness> {
  const app = createHttpApp({
    factory: () => {
      const server = new McpServer({ name: 'nutrihelp-mcp-server', version: '1.0.0' });
      // Pass both origin hostnames AND the backend API origin expected by config
      registerNutritionLookup(server, {
        port: 0,
        allowedOriginHostnames: [...ALLOWED_ORIGIN_HOSTNAMES],
        nutrihelpApiUrl: process.env.NUTRIHELP_API_URL || 'http://localhost:8081',
      } as any);
      return server;
    },
    allowedOriginHostnames: [...ALLOWED_ORIGIN_HOSTNAMES],
  });

  const server: Server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });

  const address = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${address.port}/mcp`,
    async close(): Promise<void> {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

describe('MCP Tools Direct Test Suite (OAuth Bypass)', () => {
  let harness: TestHarness;

  beforeAll(async () => {
    harness = await startTestServer();
  });

  afterAll(async () => {
    await harness.close();
    await localDispatcher.close();
  });

  it('lists registered tools successfully', async () => {
    const response = await request(harness.baseUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': PROTOCOL_REVISION,
        'mcp-method': 'tools/list',
        origin: ALLOWED_ORIGIN,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {
          _meta: REQUEST_ENVELOPE,
        },
      }),
      dispatcher: localDispatcher,
    });

    const bodyText = await response.body.text();
    expect(response.statusCode).toBe(200);
    expect(bodyText).toContain('nutrition_lookup');
  });

  it('executes nutrition_lookup and returns bounded food data without leaking user identity', async () => {
    const response = await request(harness.baseUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': PROTOCOL_REVISION,
        'mcp-method': 'tools/call',
        'mcp-name': 'nutrition_lookup',
        origin: ALLOWED_ORIGIN,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 7,
        method: 'tools/call',
        params: {
          name: 'nutrition_lookup',
          arguments: { query: 'chicken breast' },
          _meta: REQUEST_ENVELOPE,
        },
      }),
      dispatcher: localDispatcher,
    });

    const bodyText = await response.body.text();

    expect(response.statusCode).toBe(200);
    // Case-insensitive match or check for returned structure
    expect(bodyText.toLowerCase()).toContain('chicken breast');
    expect(bodyText).toContain('calories');

    for (const forbiddenKey of IDENTITY_DENY_LIST) {
      expect(bodyText).not.toContain(`"${forbiddenKey}"`);
    }
  });
});