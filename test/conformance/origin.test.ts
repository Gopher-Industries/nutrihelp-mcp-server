/**
 * Ticket 23: the Origin policy.
 *
 *   absent          -> PASS   (non-browser MCP clients send none; rejecting breaks them)
 *   empty string    -> PASS   (indistinguishable from absent once parsed)
 *   allowlisted     -> PASS   (hostname match, port-agnostic)
 *   literal "null"  -> REJECT (a *present* value, from a sandboxed or opaque browser origin)
 *   other hostname  -> REJECT
 *
 * "Absent passes" and "`null` passes" are NOT the same relaxation, and conflating them is how a
 * browser-originated request slips through. That split is what these cases pin.
 *
 * This fixture takes the explicit no-authorization opt-out, and no case carries a token. That is
 * forced rather than convenient: the accepted cases assert the request reaches the JSON-RPC
 * dispatcher, and an authorizing endpoint answers 401 to a request with no credential, so every one
 * of them would fail for a reason that has nothing to do with Origin.
 *
 * The consequence is that this file cannot pin the ORDER between the Origin guard and
 * authorization. That is asserted in `test/unit/transport/http.test.ts`, which drives an authorizing
 * endpoint with spies and shows that a disallowed origin refuses before validation, the scope check
 * and dispatch.
 */

import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { request, Agent } from 'undici';
import {
  McpServer,
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from '@modelcontextprotocol/server';
import { createHttpApp } from '../../src/transport/http.ts';
import { protectedResourceMetadata } from '../../src/auth/metadata.ts';
import {
  ALLOWED_ORIGIN,
  ALLOWED_ORIGIN_HOSTNAMES,
  MCP_AUTH_SERVER_URL,
  MCP_RESOURCE_IDENTIFIER,
} from '../support/testEnv.ts';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

const PROTOCOL_REVISION = '2026-07-28';

/** Measured 2026-08-05 from `originValidation`. Pinned, not assumed. */
const ORIGIN_REJECTED_STATUS = 403;

/** The JSON-RPC error code `originValidation` answers with. Pinned alongside the status. */
const ORIGIN_REJECTED_RPC_CODE = -32000;

/** Required `_meta` envelope. Without it the SDK returns 400/-32602 before dispatch, and
 *  `status !== 403` would pass vacuously. */
const REQUEST_ENVELOPE: Record<string, unknown> = {
  [PROTOCOL_VERSION_META_KEY]: PROTOCOL_REVISION,
  [CLIENT_INFO_META_KEY]: { name: 'nutrihelp-conformance', version: '1.0.0' },
  [CLIENT_CAPABILITIES_META_KEY]: {},
};

/** A dispatcher for the local server only; never the mocked global one. */
const localDispatcher = new Agent({ keepAliveTimeout: 10, keepAliveMaxTimeout: 10 });

interface Harness {
  readonly origin: string;
  /** Errors reported by the transport's `onError`, at every layer that accepts one. */
  readonly errors: readonly Error[];
  close(): Promise<void>;
}

async function start(): Promise<Harness> {
  const errors: Error[] = [];
  const app = createHttpApp({
    factory: () => new McpServer({ name: 'nutrihelp-mcp-server', version: '1.0.0' }),
    allowedOriginHostnames: [...ALLOWED_ORIGIN_HOSTNAMES],
    resourceMetadata: protectedResourceMetadata({
      resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
      authorizationServers: [MCP_AUTH_SERVER_URL],
    }),
    // The Origin guard runs before authentication, so these cases carry no credential and an
    // authorizing endpoint would answer 401 for every one of them. The opt-out is stated rather
    // than implied: omitting the field builds an endpoint that authorizes nothing, which reads
    // identically to forgetting it, and this is the fixture whose silence made that shape
    // survivable in the first place.
    authorization: { unauthenticated: 'transport-tests-only' },
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

/** `origin: undefined` omits the header; that is not the same as an empty string. */
interface Probe {
  readonly status: number;
  readonly body: string;
  readonly rpcCode: number | undefined;
  readonly rpcId: unknown;
}

async function post(harness: Harness, origin: string | undefined): Promise<Probe> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-protocol-version': PROTOCOL_REVISION,
    'mcp-method': 'tools/list',
  };
  if (origin !== undefined) headers.origin = origin;

  const response = await request(`${harness.origin}/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: { _meta: REQUEST_ENVELOPE },
    }),
    dispatcher: localDispatcher,
  });

  const body = await response.body.text();

  // The SDK answers either plain JSON or an SSE frame; read out of whichever arrived.
  let rpcCode: number | undefined;
  let rpcId: unknown;
  const payload = body
    .split('\n')
    .map((line) => (line.startsWith('data:') ? line.slice('data:'.length).trim() : line))
    .join('');
  try {
    const parsed = JSON.parse(payload) as { id?: unknown; error?: { code?: unknown } } | null;
    if (typeof parsed?.error?.code === 'number') rpcCode = parsed.error.code;
    rpcId = parsed?.id;
  } catch {
    rpcCode = undefined;
  }

  return { status: response.statusCode, body, rpcCode, rpcId };
}

/** Past the Origin guard: echoed request id proves dispatch, not merely `status !== 403`. */
function expectPassedOriginGuard(result: Probe, context: string): void {
  expect(
    result.rpcId,
    `${context}: the request must reach the JSON-RPC dispatcher, which echoes the request id. An Origin rejection answers id:null before that point`
  ).toBe(1);
  expect(result.status, `${context}: not refused by the Origin guard`).not.toBe(
    ORIGIN_REJECTED_STATUS
  );
  expect(result.rpcCode, `${context}: no Origin rejection in the JSON-RPC envelope`).not.toBe(
    ORIGIN_REJECTED_RPC_CODE
  );
  expect(result.body, `${context}: no Origin rejection in the body`).not.toContain(
    'Invalid Origin'
  );
}

/** Assert a request was refused BY THE ORIGIN GUARD, not by something else that also fails. */
function expectRejectedByOriginGuard(result: Probe, context: string): void {
  expect(result.status, `${context}: refused with the measured Origin status`).toBe(
    ORIGIN_REJECTED_STATUS
  );
  expect(result.body, `${context}: refused BY THE ORIGIN GUARD specifically`).toContain(
    'Invalid Origin'
  );
  expect(result.rpcCode, `${context}: the Origin rejection carries its own JSON-RPC code`).toBe(
    ORIGIN_REJECTED_RPC_CODE
  );
}

let harness: Harness;

beforeEach(async () => {
  harness = await start();
});

afterEach(async () => {
  await harness.close();
});

afterAll(async () => {
  await localDispatcher.close();
});

describe('Origin policy at the transport boundary (ticket 23)', () => {
  describe('accepted', () => {
    it('passes a request with no Origin header at all', async () => {
      expectPassedOriginGuard(
        await post(harness, undefined),
        'absent Origin: non-browser MCP clients send none, and rejecting it breaks every such client'
      );
    });

    it('passes a request with an empty-string Origin', async () => {
      expectPassedOriginGuard(
        await post(harness, ''),
        'empty-string Origin is indistinguishable from absent once parsed, and is treated the same'
      );
    });

    it('passes an allowlisted Origin', async () => {
      expectPassedOriginGuard(
        await post(harness, ALLOWED_ORIGIN),
        `${ALLOWED_ORIGIN} is on MCP_ALLOWED_ORIGINS and must reach the handler`
      );
    });

    it('passes an allowlisted hostname on a different port', async () => {
      expectPassedOriginGuard(
        await post(harness, `${ALLOWED_ORIGIN}:8443`),
        'the allowlist matches on hostname and is port-agnostic'
      );
    });
  });

  describe('rejected', () => {
    it('rejects a literal "null" Origin with 403', async () => {
      expectRejectedByOriginGuard(
        await post(harness, 'null'),
        'literal "null" is a PRESENT Origin from a sandboxed or opaque browser context, and must not inherit the absent-Origin pass'
      );
    });

    it('rejects a non-allowlisted hostname with 403', async () => {
      expectRejectedByOriginGuard(
        await post(harness, 'https://evil.test'),
        'an origin outside the allowlist is refused'
      );
    });

    it('rejects a preview domain with 403', async () => {
      expectRejectedByOriginGuard(
        await post(harness, 'https://nutrihelp-git-feature.vercel.app'),
        'the backend CORS function accepts any *.vercel.app origin with credentials; this server does not inherit it'
      );
    });

    it('rejects a malformed Origin with 403', async () => {
      expectRejectedByOriginGuard(
        await post(harness, 'not-a-url'),
        'an unparseable Origin cannot be matched against the allowlist and is refused rather than skipped'
      );
    });

    it('rejects an allowlisted hostname carrying userinfo with 403', async () => {
      expectRejectedByOriginGuard(
        await post(harness, `https://claude.ai@evil.test`),
        'userinfo before the host is a classic allowlist-parsing bypass: the real host is evil.test'
      );
    });

    it('rejects a subdomain of an allowlisted host with 403', async () => {
      expectRejectedByOriginGuard(
        await post(harness, 'https://sub.claude.ai'),
        'the allowlist is exact hostnames, never a wildcard subdomain'
      );
    });

    it('rejects a host that merely ends with the allowlisted name', async () => {
      expectRejectedByOriginGuard(
        await post(harness, 'https://claude.ai.evil.test'),
        'a suffix match would admit claude.ai.evil.test. The comparison is on the whole hostname'
      );
    });

    it('discriminates rather than refusing everything', async () => {
      const allowed = await post(harness, ALLOWED_ORIGIN);
      const refused = await post(harness, 'https://evil.test');

      expect(refused.status, 'anti-vacuity: the disallowed origin must be refused').toBe(
        ORIGIN_REJECTED_STATUS
      );
      expect(
        allowed.status,
        'anti-vacuity: an endpoint hard-wired to 403 would pass every other case in this describe block. The allowlisted origin must NOT be refused'
      ).not.toBe(ORIGIN_REJECTED_STATUS);
    });
  });

  describe('the rejection happens before dispatch', () => {
    it('does not report a handler error when an Origin is refused', async () => {
      await post(harness, 'https://evil.test');
      expect(
        harness.errors,
        'the Origin check runs before authentication and dispatch, so a refused request must never reach the MCP handler. An error here means it did'
      ).toHaveLength(0);
    });
  });
});
