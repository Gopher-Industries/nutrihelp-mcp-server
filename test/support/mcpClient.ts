/**
 * The transport-level harness. Every security test drives the real `/mcp` endpoint built by
 * `createHttpApp` and asserts on the wire response — status code, `WWW-Authenticate`, JSON-RPC
 * error shape — never on an internal type name.
 *
 * That is what makes the suite writable before the code exists: `src/errors.ts` is blocked on
 * ticket 55, and a test naming `McpError` would block this ticket behind that one.
 *
 * Requests are issued with an explicit `undici` `Agent`, so they bypass the `MockAgent`
 * installed on the global dispatcher. `test/**` carries the flat-config exemption that lets
 * this file import `undici` at all; the `fetch` guard stays on.
 */

import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Agent, request } from 'undici';
import { McpServer } from '@modelcontextprotocol/server';
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from '@modelcontextprotocol/server';
import { createHttpApp } from '../../src/transport/http.ts';
import { ALLOWED_ORIGIN, ALLOWED_ORIGIN_HOSTNAMES } from './testEnv.ts';

/** The one revision this server speaks. Selected explicitly, not negotiated. */
export const PROTOCOL_REVISION = '2026-07-28';

/**
 * The per-request `_meta` envelope every 2026-07-28 request carries. Without it the SDK
 * rejects at the protocol boundary with `-32602` before anything under test is reached, so it
 * belongs in the harness rather than in each case.
 */
const REQUEST_ENVELOPE: Record<string, unknown> = {
  [PROTOCOL_VERSION_META_KEY]: PROTOCOL_REVISION,
  [CLIENT_INFO_META_KEY]: { name: 'nutrihelp-security-suite', version: '1.0.0' },
  [CLIENT_CAPABILITIES_META_KEY]: {},
};

export interface TestServer {
  readonly origin: string;
  readonly errors: readonly Error[];
  close(): Promise<void>;
}

/**
 * Start the transport exactly as `src/server.ts` composes it.
 *
 * NOTE, and it is the honest limitation of writing this suite first: `createHttpApp` currently
 * takes no authorization wiring, because none exists. When tickets 21-32 land the composition
 * root gains a token validator, a revocation checker and a registry, and this factory is the
 * single place that has to learn about them. Every test below goes through here for that
 * reason.
 */
export async function startTestServer(): Promise<TestServer> {
  const errors: Error[] = [];
  const app = createHttpApp({
    factory: () => new McpServer({ name: 'nutrihelp-mcp-server', version: '1.0.0' }),
    allowedOriginHostnames: [...ALLOWED_ORIGIN_HOSTNAMES],
    onError: (error: Error) => errors.push(error),
  });

  const server: Server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => {
      resolve();
    });
    server.once('error', reject);
  });

  const address = server.address() as AddressInfo;

  return {
    origin: `http://127.0.0.1:${String(address.port)}`,
    errors,
    async close(): Promise<void> {
      server.closeAllConnections();
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    },
  };
}

/** A dispatcher reserved for talking to the local test server. Never the mocked one. */
// Module-level, and closed by each file's `afterAll`. Safe only because Vitest isolates by
// file: under `isolate: false` the first file to finish would close it for every later one.
const localDispatcher = new Agent({ keepAliveTimeout: 10, keepAliveMaxTimeout: 10 });

export async function closeLocalDispatcher(): Promise<void> {
  await localDispatcher.close();
}

export interface JsonRpcError {
  readonly code: number;
  readonly message: string;
  readonly data?: unknown;
}

export interface McpResponse {
  readonly status: number;
  readonly headers: Record<string, string | string[] | undefined>;
  /** The parsed JSON-RPC envelope, or `undefined` when the body was not JSON-RPC. */
  readonly rpc: { id?: unknown; result?: unknown; error?: JsonRpcError } | undefined;
  readonly rawBody: string;
  /** `WWW-Authenticate`, lower-cased key, joined if repeated. */
  readonly challenge: string | undefined;
}

export interface McpRequestOptions {
  /** The JSON-RPC method, mirrored into the `Mcp-Method` routing header. */
  readonly method: string;
  /** The tool name, mirrored into `Mcp-Name` for a `tools/call`. */
  readonly name?: string;
  readonly params?: Record<string, unknown>;
  /** Presented as `Authorization: Bearer <token>`. Omitted entirely when absent. */
  readonly token?: string;
  readonly origin?: string;
  readonly id?: number;
}

function joinHeader(value: string | string[] | undefined): string | undefined {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value.join(', ') : value;
}

/**
 * Parse either a plain JSON body or a Streamable-HTTP SSE frame. The SDK may answer in either
 * shape, and a test that only understood one would report a protocol difference as a security
 * failure.
 */
function parseRpc(contentType: string | undefined, body: string): McpResponse['rpc'] {
  const payload =
    contentType?.includes('text/event-stream') === true
      ? body
          .split('\n')
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice('data:'.length).trim())
          .join('') || ''
      : body;

  if (payload.trim() === '') return undefined;
  try {
    const parsed: unknown = JSON.parse(payload);
    if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
      return parsed;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

export async function mcpRequest(
  server: TestServer,
  options: McpRequestOptions
): Promise<McpResponse> {
  const { method, name, params = {}, token, origin = ALLOWED_ORIGIN, id = 1 } = options;

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': PROTOCOL_REVISION,
    'mcp-method': method,
    origin,
  };
  if (name !== undefined) headers['mcp-name'] = name;
  if (token !== undefined) headers.authorization = `Bearer ${token}`;

  const response = await request(`${server.origin}/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id,
      method,
      params: { ...params, _meta: { ...REQUEST_ENVELOPE, ...(params._meta ?? {}) } },
    }),
    dispatcher: localDispatcher,
  });

  const rawBody = await response.body.text();
  const responseHeaders = response.headers as Record<string, string | string[] | undefined>;

  return {
    status: response.statusCode,
    headers: responseHeaders,
    rawBody,
    rpc: parseRpc(joinHeader(responseHeaders['content-type']), rawBody),
    challenge: joinHeader(responseHeaders['www-authenticate']),
  };
}

/** `tools/list`. Live introspection runs for this too — it is not exempt. */
export async function listTools(server: TestServer, token?: string): Promise<McpResponse> {
  return mcpRequest(server, {
    method: 'tools/list',
    ...(token === undefined ? {} : { token }),
  });
}

/** `tools/call`, with the `Mcp-Name` routing header set to match the body. */
export async function callTool(
  server: TestServer,
  toolName: string,
  args: Record<string, unknown>,
  token?: string
): Promise<McpResponse> {
  return mcpRequest(server, {
    method: 'tools/call',
    name: toolName,
    params: { name: toolName, arguments: args },
    ...(token === undefined ? {} : { token }),
  });
}

/**
 * The model-facing half of a `tools/call` result, as the assistant would see it.
 * Returns `undefined` when the call did not produce a tool result at all, which is what every
 * one of these tests hits today.
 */
export interface ToolResultView {
  readonly isError: boolean;
  /** Everything the model can read, flattened for substring assertions. */
  readonly text: string;
  readonly structured: unknown;
}

export function toolResult(response: McpResponse): ToolResultView | undefined {
  const result = response.rpc?.result;
  if (typeof result !== 'object' || result === null) return undefined;

  const record = result as Record<string, unknown>;
  const content = Array.isArray(record.content) ? record.content : [];
  const text = content
    .map((block) =>
      typeof block === 'object' &&
      block !== null &&
      typeof (block as { text?: unknown }).text === 'string'
        ? (block as { text: string }).text
        : JSON.stringify(block)
    )
    .join('\n');

  return {
    isError: record.isError === true,
    text: `${text}\n${JSON.stringify(record.structuredContent ?? {})}`,
    structured: record.structuredContent,
  };
}
