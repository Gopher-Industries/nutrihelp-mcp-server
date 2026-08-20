/**
 * Mandatory auth order, asserted with spies. Exact-equality sequences: inserting live
 * introspection between validation and scope must break four cases on purpose.
 */

import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Agent, request } from 'undici';
import {
  McpServer,
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from '@modelcontextprotocol/server';
import type { JWTPayload } from 'jose';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import { createHttpApp, type RequestRouting } from '../../../src/transport/http.ts';
import type { TokenValidator } from '../../../src/auth/tokenValidator.ts';
import { protectedResourceMetadata } from '../../../src/auth/metadata.ts';
import {
  ALL_SCOPES,
  ALLOWED_ORIGIN,
  ALLOWED_ORIGIN_HOSTNAMES,
  CLIENT_ID,
  GRANT_A,
  MCP_AUTH_SERVER_URL,
  MCP_RESOURCE_IDENTIFIER,
  RESOURCE_METADATA_URL,
  SCOPES,
  USER_A,
} from '../../support/testEnv.ts';

const PROTOCOL_REVISION = '2026-07-28';

/**
 * The credential is an opaque string, never a real JWT, precisely so that the claims the scope
 * resolver receives can only have come from the validator's return value. Nothing in this file
 * could read `USER_A` out of `OPAQUE_CREDENTIAL`.
 */
const OPAQUE_CREDENTIAL = 'a-credential-this-suite-never-parses';

/** What the accepting validator hands back. Its `sub` appears nowhere in the credential. */
const VERIFIED_CLAIMS: JWTPayload = {
  sub: USER_A,
  scope: ALL_SCOPES.join(' '),
  client_id: CLIENT_ID,
  grant_id: GRANT_A,
};

/** The sentinel encoded form: a routing value that is not already plain. */
const ENCODED_ROUTING_VALUE = '=?utf-8?B?dG9vbHMvbGlzdA==?=';

const localDispatcher = new Agent({ keepAliveTimeout: 10, keepAliveMaxTimeout: 10 });

interface ProbeConfig {
  /** Whether offline validation succeeds. A rejection is a plain `Error`: this file asserts
   *  ordering, and coupling it to a jose error class would make it a test of the code mapping. */
  readonly validator: 'accepts' | 'rejects';
  /** Returned by the injected resolver. `undefined` means the granted scopes suffice. */
  readonly missingScope?: string;
  /** Throw inside the resolver, to prove an unexpected fault closes the request rather than
   *  falling through to dispatch. */
  readonly scopeThrows?: boolean;
  /**
   * Build the transport with no `onError` at all. Every other fixture in the repository supplies
   * one, which leaves the reporter-absent arms of this module untaken and, more importantly, leaves
   * untested whether a fault with nowhere to report still closes the request rather than escaping
   * the handler.
   */
  readonly omitOnError?: boolean;
}

interface ProbeRequest {
  readonly methodHeader?: string;
  readonly nameHeader?: string;
  /** Sent verbatim. Absent means no `Authorization` header at all. */
  readonly authorization?: string;
  /** Defaults to the allowlisted origin. Overridden only to pin the guard that runs before all
   *  of the steps below. */
  readonly origin?: string;
}

interface ProbeResponse {
  readonly status: number;
  readonly challenge: string | undefined;
  readonly rpcId: unknown;
  readonly rpcCode: number | undefined;
  readonly body: string;
}

interface Probe {
  /** Every collaborator that ran, in the order it ran. */
  readonly steps: readonly string[];
  /** What `onError` was told, which is all the composition root logs. */
  readonly reports: readonly string[];
  /** The arguments the scope resolver was handed. */
  readonly scopeArgs: readonly { routing: RequestRouting; claims: JWTPayload }[];
  send(options?: ProbeRequest): Promise<ProbeResponse>;
  close(): Promise<void>;
}

async function startProbe(config: ProbeConfig): Promise<Probe> {
  const steps: string[] = [];
  const reports: string[] = [];
  const scopeArgs: { routing: RequestRouting; claims: JWTPayload }[] = [];

  const validator: TokenValidator = {
    validate(): Promise<JWTPayload> {
      steps.push('validate');
      return config.validator === 'accepts'
        ? Promise.resolve(VERIFIED_CLAIMS)
        : Promise.reject(new Error('the injected validator refuses this credential'));
    },
  };

  const app = createHttpApp({
    factory: () => {
      steps.push('dispatch');
      return new McpServer({ name: 'nutrihelp-mcp-server', version: '1.0.0' });
    },
    allowedOriginHostnames: [...ALLOWED_ORIGIN_HOSTNAMES],
    resourceMetadata: protectedResourceMetadata({
      resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
      authorizationServers: [MCP_AUTH_SERVER_URL],
    }),
    authorization: {
      validator,
      missingScopeFor: (routing: RequestRouting, claims: JWTPayload): string | undefined => {
        steps.push('scope');
        scopeArgs.push({ routing, claims });
        if (config.scopeThrows === true) {
          throw new Error('the injected scope resolver faulted');
        }
        return config.missingScope;
      },
    },
    ...(config.omitOnError === true
      ? {}
      : { onError: (error: Error) => reports.push(error.message) }),
  });

  const server: Server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('listening', () => {
      resolve();
    });
    server.once('error', reject);
  });
  const address = server.address() as AddressInfo;
  const origin = `http://127.0.0.1:${String(address.port)}`;

  return {
    steps,
    reports,
    scopeArgs,
    async send(options: ProbeRequest = {}): Promise<ProbeResponse> {
      const headers: Record<string, string> = {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': PROTOCOL_REVISION,
        'mcp-method': options.methodHeader ?? 'tools/list',
        origin: options.origin ?? ALLOWED_ORIGIN,
      };
      if (options.nameHeader !== undefined) headers['mcp-name'] = options.nameHeader;
      if (options.authorization !== undefined) headers.authorization = options.authorization;

      const response = await request(`${origin}/mcp`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/list',
          // The required envelope. Without it the SDK refuses at the protocol boundary before
          // dispatch, and the granting case below would read as "reached dispatch" while never
          // having done so.
          params: {
            _meta: {
              [PROTOCOL_VERSION_META_KEY]: PROTOCOL_REVISION,
              [CLIENT_INFO_META_KEY]: { name: 'nutrihelp-order-suite', version: '1.0.0' },
              [CLIENT_CAPABILITIES_META_KEY]: {},
            },
          },
        }),
        dispatcher: localDispatcher,
      });

      const raw = await response.body.text();
      const payload = raw
        .split('\n')
        .map((line) => (line.startsWith('data:') ? line.slice('data:'.length).trim() : line))
        .join('');

      let rpcId: unknown;
      let rpcCode: number | undefined;
      try {
        const parsed = JSON.parse(payload) as { id?: unknown; error?: { code?: unknown } } | null;
        rpcId = parsed?.id;
        if (typeof parsed?.error?.code === 'number') rpcCode = parsed.error.code;
      } catch {
        rpcId = undefined;
      }

      const challengeHeader = response.headers['www-authenticate'];
      return {
        status: response.statusCode,
        challenge: Array.isArray(challengeHeader) ? challengeHeader.join(', ') : challengeHeader,
        rpcId,
        rpcCode,
        body: raw,
      };
    },
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

let probe: Probe | undefined;

async function start(config: ProbeConfig): Promise<Probe> {
  probe = await startProbe(config);
  return probe;
}

afterEach(async () => {
  await probe?.close();
  probe = undefined;
});

afterAll(async () => {
  await localDispatcher.close();
});

describe('the mandatory order at the authorization boundary', () => {
  /**
   * Step 0. The Origin guard runs before any of it.
   *
   * This case lives here rather than in the Origin suite because that suite drives an endpoint with
   * the explicit no-authorization opt-out — it has to, since its five accepted cases assert the
   * request reaches the dispatcher and an authorizing endpoint would answer 401 to all of them. So
   * this is the only place the ordering between the two guards is observable.
   *
   * The discrimination matters: an Origin refusal and an insufficient-scope refusal are BOTH 403.
   * What separates them is the body and the empty step list.
   */
  it('refuses a disallowed Origin before any authorization step runs', async () => {
    const p = await start({ validator: 'accepts', missingScope: SCOPES.meallogWrite });

    const response = await p.send({
      origin: 'https://evil.test',
      authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
    });

    expect(response.status, 'the measured Origin rejection status').toBe(403);
    expect(
      response.body,
      'refused BY THE ORIGIN GUARD specifically. An insufficient-scope refusal is also 403, and carries no body at all'
    ).toContain('Invalid Origin');
    expect(
      response.challenge,
      'and no Bearer challenge: the Origin guard says nothing about the credential'
    ).toBeUndefined();
    expect(
      p.steps,
      'a request from a disallowed origin must not reach validation, the scope check or dispatch — the credential it carried was valid and the scope it needed was missing, so any later step would have left a mark'
    ).toEqual([]);
    expect(p.reports, 'the Origin guard answers without reporting through onError').toEqual([]);
  });

  /**
   * Step 1 before everything that follows. The request carries a perfectly good credential and
   * would fail the scope check, so a 400 rather than a 401 or a 403 is the only outcome that puts
   * the routing shape first.
   */
  it('refuses a routing value that is not already plain before reading the credential', async () => {
    const p = await start({ validator: 'accepts', missingScope: SCOPES.meallogWrite });

    const response = await p.send({
      nameHeader: ENCODED_ROUTING_VALUE,
      authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
    });

    expect(
      response.status,
      'a malformed routing value is a bad request, not an authorization outcome'
    ).toBe(400);
    expect(
      response.challenge,
      'a Bearer challenge here would send a client to reauthorize over a malformed header, which reauthorizing cannot fix'
    ).toBeUndefined();
    expect(
      p.steps,
      'nothing after the routing check may run: the credential was valid and the scope insufficient, so any later step would have produced 401 or 403 instead'
    ).toEqual([]);
    expect(p.reports).toContain('bad_request.routing_header_not_plain');
  });

  /**
   * The header shape is checked whether or not anything reads the value. Gating it on the presence
   * of a scope resolver would mean the next reader of these values inherits an unvalidated name.
   */
  it('refuses a malformed Mcp-Method as well as a malformed Mcp-Name', async () => {
    const p = await start({ validator: 'accepts' });

    const response = await p.send({
      methodHeader: ENCODED_ROUTING_VALUE,
      authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
    });

    expect(response.status).toBe(400);
    expect(p.steps).toEqual([]);
    expect(
      p.reports,
      'refused by the plain-form guard specifically, not by a layer in front of it that also answers 400'
    ).toContain('bad_request.routing_header_not_plain');
  });

  /** Step 2 before step 3. No credential to validate means the validator is never reached. */
  it('answers an absent credential without calling the validator or the scope resolver', async () => {
    const p = await start({ validator: 'accepts', missingScope: SCOPES.meallogWrite });

    const response = await p.send();

    expect(response.status).toBe(401);
    expect(response.challenge, 'the challenge that starts the connect flow carries no error').toBe(
      `Bearer resource_metadata="${RESOURCE_METADATA_URL}"`
    );
    expect(
      p.steps,
      'credential extraction precedes offline validation, so there is nothing to validate here'
    ).toEqual([]);
    expect(
      p.reports,
      'an absent header is the first half of the connect flow and is not an operator signal'
    ).toEqual([]);
  });

  it('reports a present but unparseable credential, and still calls nothing', async () => {
    const p = await start({ validator: 'accepts' });

    const response = await p.send({ authorization: 'Basic dXNlcjpwYXNz' });

    expect(response.status).toBe(401);
    expect(p.steps).toEqual([]);
    expect(
      p.reports,
      'a header that is present and unparseable is a broken client or a probe, and is the one an operator wants to see'
    ).toContain('unauthorized.malformed_credential');
  });

  /** Step 3 before step 4. A rejected credential never reaches a scope verdict. */
  it('does not compute a scope verdict for a credential that failed validation', async () => {
    const p = await start({ validator: 'rejects', missingScope: SCOPES.meallogWrite });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      response.status,
      'the credential failed, so this is 401 — not the 403 the insufficient scope would have produced'
    ).toBe(401);
    expect(response.challenge).toBe(
      `Bearer error="invalid_token", resource_metadata="${RESOURCE_METADATA_URL}"`
    );
    expect(p.steps, 'offline validation runs before the scope check and refuses before it').toEqual(
      ['validate']
    );
  });

  /** Step 4 before step 5. */
  it('refuses insufficient scope before dispatch, with 403 and never 401', async () => {
    const p = await start({ validator: 'accepts', missingScope: SCOPES.meallogWrite });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.status).toBe(403);
    expect(
      response.status,
      'a 401 here would push the client into refresh-and-retry over a scope refreshing will never grant'
    ).not.toBe(401);
    expect(p.steps, 'validation then scope, and dispatch never').toEqual(['validate', 'scope']);
  });

  /**
   * The granting case. Without it every assertion above is satisfied by an endpoint that refuses
   * everything, and the recorded sequence would never show more than two entries.
   */
  it('runs every step in order and reaches dispatch when nothing refuses', async () => {
    const p = await start({ validator: 'accepts' });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      p.steps,
      'the whole realised order, in one assertion: offline validation, then the scope check, then dispatch'
    ).toEqual(['validate', 'scope', 'dispatch']);
    expect(
      response.rpcId,
      'a positive discriminator rather than a status exclusion: only the JSON-RPC layer echoes the request id, and every refusal above answers before it'
    ).toBe(1);
    expect(response.status, 'nothing refused this request').not.toBe(401);
    expect(response.status).not.toBe(403);
    expect(response.challenge, 'a served request carries no challenge').toBeUndefined();
    expect(p.reports, 'a served request reports nothing').toEqual([]);
  });

  it('hands the scope resolver the plain routing values and the verified claims', async () => {
    const p = await start({ validator: 'accepts' });

    await p.send({
      methodHeader: 'tools/call',
      nameHeader: 'get-meal-plan',
      authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
    });

    expect(p.scopeArgs).toHaveLength(1);
    const [call] = p.scopeArgs;
    expect(call?.routing).toEqual({ method: 'tools/call', name: 'get-meal-plan' });
    expect(
      call?.claims.sub,
      'the scope decision is computed from the VERIFIED claims. This subject appears nowhere in the credential the request presented, so it can only have come from the validator'
    ).toBe(USER_A);
    expect(OPAQUE_CREDENTIAL).not.toContain(USER_A);
  });

  it('reports an absent Mcp-Name as absent rather than as an empty name', async () => {
    const p = await start({ validator: 'accepts' });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      p.scopeArgs[0]?.routing,
      'an absent routing header is legitimate and must not arrive as an empty string, which a name comparison would treat as a name'
    ).toEqual({ method: 'tools/list', name: undefined });
  });

  /**
   * Fail closed. This assertion never skips in any environment: a fault in the authorization path
   * that fell through to dispatch would be an unauthorized call, not a degraded one.
   */
  it('closes the request rather than dispatching when the authorization path faults', async () => {
    const p = await start({ validator: 'accepts', scopeThrows: true });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.status, 'an unexpected fault closes the request').toBe(500);
    expect(
      response.challenge,
      'a fault says nothing about the credential, so it carries no challenge'
    ).toBeUndefined();
    expect(p.steps, 'the fault must not fall through to dispatch').toEqual(['validate', 'scope']);
    expect(p.steps).not.toContain('dispatch');
  });

  /**
   * The same fail-closed property with no reporter attached. `onError` is optional, so an endpoint
   * can be built without one, and "closes the request" must not quietly depend on there being
   * somewhere to report the fault to. Never skips.
   */
  it('closes the request on a fault even with no error reporter attached', async () => {
    const p = await start({ validator: 'accepts', scopeThrows: true, omitOnError: true });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.status, 'still 500, not a hung request and not a fall-through').toBe(500);
    expect(response.challenge).toBeUndefined();
    expect(p.steps, 'and still no dispatch').toEqual(['validate', 'scope']);
    expect(p.reports, 'nothing was reported, because there was nowhere to report it').toEqual([]);
  });

  /** The granting path with no reporter, so the case above is not the only thing exercising it. */
  it('serves a request with no error reporter attached', async () => {
    const p = await start({ validator: 'accepts', omitOnError: true });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.rpcId, 'reached the dispatcher').toBe(1);
    expect(p.steps).toEqual(['validate', 'scope', 'dispatch']);
  });
});
