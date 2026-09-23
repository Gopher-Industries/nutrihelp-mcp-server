import { unavailableConfirmations } from '../../support/confirmationFixture.ts';
/**
 * Mandatory auth order, asserted with spies. Exact-equality sequences: insert/remove/reorder
 * breaks a case rather than a position-blind `toContain`.
 *
 * Live introspection sits between offline validation and scope — no exemption, never cached here.
 */

import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { Agent, request } from 'undici';
import {
  McpServer,
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
  type AuthInfo,
  type McpRequestContext,
} from '@modelcontextprotocol/server';
import { errors, type JWTPayload } from 'jose';
import { afterAll, afterEach, describe, expect, it } from 'vitest';
import {
  createHttpApp,
  type AuthorizationLookup,
  type AuthorizationOptions,
  type RequestRouting,
} from '../../../src/transport/http.ts';
import type {
  UpstreamCredential,
  UpstreamCredentialRequest,
} from '../../../src/auth/upstreamToken.ts';
import {
  AUDIT_ENQUEUE_NOT_IMPLEMENTED,
  registerTools,
  type AuditEnqueueEvent,
} from '../../../src/tools/registry.ts';
import {
  credentialedProbe,
  publicProbe,
  CREDENTIALED_TOOL_NAME,
  PUBLIC_TOOL_NAME,
} from '../../support/credentialedTool.ts';
import { callTool, closeLocalDispatcher, startTestServer } from '../../support/mcpClient.ts';
import { missingScopeFor as realMissingScopeFor } from '../../../src/auth/scopes.ts';
import { installUpstreamMock } from '../../support/upstreamMock.ts';
import { expectToolResult } from '../../support/assertions.ts';
import { createTestKeyPair, makeToken } from '../../../scripts/makeToken.ts';
import type { TokenValidator } from '../../../src/auth/tokenValidator.ts';
import { descriptor as nutritionLookupDescriptor } from '../../../src/tools/nutritionLookup.ts';
import type {
  ActiveGrant,
  IntrospectionRequest,
  RevocationChecker,
} from '../../../src/auth/revocation.ts';
import { McpError } from '../../../src/errors.ts';
import { protectedResourceMetadata } from '../../../src/auth/metadata.ts';
import { forgeActiveGrant } from '../../support/activeGrant.ts';
import {
  ALL_SCOPES,
  ALLOWED_ORIGIN,
  ALLOWED_ORIGIN_HOSTNAMES,
  CLIENT_ID,
  GRANT_A,
  MCP_AUTH_SERVER_URL,
  MCP_EXPECTED_ISSUER,
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

/**
 * What a granting introspection hands back. Fixed values so nothing is read out of the token.
 * Forged: `ActiveGrant` is branded by the module that mints it, and only that module can.
 */
const ACTIVE_GRANT: ActiveGrant = forgeActiveGrant({
  grantId: GRANT_A,
  scopes: ALL_SCOPES,
  subject: USER_A,
  clientId: CLIENT_ID,
});

/** The probe's request budget. Every introspection slice is measured against it. */
const PROBE_REQUEST_DEADLINE_MS = 30_000;

/**
 * Injected checker answers. Mapping is the point: authenticated `active: false` → 401 only;
 * everything else → retryable upstream failure; anything outside the taxonomy must still close.
 */
type RevocationBehaviour =
  /** Active grant. */
  | 'active'
  /** Authenticated, explicit `active: false`. */
  | 'inactive'
  /** Unreachable, timed out, 5xx, or malformed — no explicit result. */
  | 'unestablished'
  /** Something outside the taxonomy escaped the checker. */
  | 'faults'
  /** The named opt-out. No checker wired. */
  | 'disabled';

/** An `unauthorized` McpError, the only class the transport may turn into a 401. */
function inactiveGrant(): McpError {
  return new McpError({
    class: 'unauthorized',
    reason: 'authorization server reported the grant inactive',
    resourceMetadataUrl: RESOURCE_METADATA_URL,
  });
}

/** The retryable class every other introspection outcome arrives as. */
function unestablishedGrant(): McpError {
  return new McpError({
    class: 'upstream_failure',
    statusClass: '5xx',
    errorCode: 'introspection_status',
    endpointClass: 'authorization_server_introspection',
    correlationId: 'probe-correlation-id',
    latencyMs: 1,
  });
}

const localDispatcher = new Agent({ keepAliveTimeout: 10, keepAliveMaxTimeout: 10 });

interface ProbeConfig {
  /** Whether offline validation succeeds. A rejection defaults to a plain `Error`: this file asserts
   *  ordering, and coupling it to a jose error class would make it a test of the code mapping. */
  readonly validator: 'accepts' | 'rejects';
  /** Rejection cause for classifier-mapping cases. Fall-through is unreachable via real tokens. */
  readonly validatorRejectsWith?: Error;
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
  /** Defaults to `'active'`: introspection runs on every request and the grant is live. */
  readonly revocation?: RevocationBehaviour;
  /**
   * Offline-validation spend (ms). Injects a fake clock advancing by this amount so the
   * introspection slice is arithmetic. Absent → real clock (distinct arm; proves default works).
   */
  readonly validationCostMs?: number;
  /**
   * Register tools on the per-request server, so the steps AFTER dispatch — the registry's own
   * half of the mandatory order — are observable in the same sequence as the transport's.
   */
  readonly register?: (
    server: McpServer,
    ctx: McpRequestContext,
    authorizationFor: AuthorizationLookup,
    steps: string[]
  ) => void;
}

interface ProbeRequest {
  readonly methodHeader?: string;
  readonly nameHeader?: string;
  /** Sent verbatim. Absent means no `Authorization` header at all. */
  readonly authorization?: string;
  /** Defaults to the allowlisted origin. Overridden only to pin the guard that runs before all
   *  of the steps below. */
  readonly origin?: string;
  /** JSON-RPC method in the BODY. Defaults to `tools/list`; a six-step case needs `tools/call`. */
  readonly rpcMethod?: string;
  /** Extra JSON-RPC params, merged under the required `_meta` envelope. */
  readonly rpcParams?: Record<string, unknown>;
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
  /** The arguments the scope resolver was handed, including the grant introspection established. */
  readonly scopeArgs: readonly {
    routing: RequestRouting;
    claims: JWTPayload;
    grant: ActiveGrant | undefined;
  }[];
  /** Every step-4 credential request, in order. Empty unless a credentialed tool dispatched. */
  readonly credentialRequests: readonly UpstreamCredentialRequest[];
  /** Every live-introspection request, in order. Empty under the named opt-out. */
  readonly introspections: readonly IntrospectionRequest[];
  send(options?: ProbeRequest): Promise<ProbeResponse>;
  close(): Promise<void>;
}

async function startProbe(config: ProbeConfig): Promise<Probe> {
  const steps: string[] = [];
  const reports: string[] = [];
  const scopeArgs: {
    routing: RequestRouting;
    claims: JWTPayload;
    grant: ActiveGrant | undefined;
  }[] = [];
  const introspections: IntrospectionRequest[] = [];
  const credentialRequests: UpstreamCredentialRequest[] = [];

  const behaviour: RevocationBehaviour = config.revocation ?? 'active';

  /**
   * Fake clock origin is a large non-zero: starting at 0 lets forgetting `startedAt` look correct
   * (`clock() - 0` === `clock()`).
   */
  let clockMs = 1_700_000_000_000;

  const checker: RevocationChecker = {
    assertGrantActive: (introspection: IntrospectionRequest): Promise<ActiveGrant> => {
      steps.push('introspect');
      introspections.push(introspection);
      switch (behaviour) {
        case 'inactive':
          return Promise.reject(inactiveGrant());
        case 'unestablished':
          return Promise.reject(unestablishedGrant());
        case 'faults':
          // Outside the taxonomy: transport must close, not fall through to dispatch.
          return Promise.reject(new TypeError('the injected revocation checker faulted'));
        default:
          return Promise.resolve(ACTIVE_GRANT);
      }
    },
  };

  const revocation: AuthorizationOptions['revocation'] =
    behaviour === 'disabled' ? { revocationDisabled: 'transport-tests-only' } : checker;

  const validator: TokenValidator = {
    validate(): Promise<JWTPayload> {
      steps.push('validate');
      // Validation spends budget (JWKS fetch); advance so the next stage's share is observable.
      clockMs += config.validationCostMs ?? 0;
      return config.validator === 'accepts'
        ? Promise.resolve(VERIFIED_CLAIMS)
        : Promise.reject(
            config.validatorRejectsWith ??
              new Error('the injected validator refuses this credential')
          );
    },
  };

  const app = createHttpApp({
    factory: (ctx, authorizationFor) => {
      steps.push('dispatch');
      const server = new McpServer({ name: 'nutrihelp-mcp-server', version: '1.0.0' });
      config.register?.(server, ctx, authorizationFor, steps);
      return server;
    },
    allowedOriginHostnames: [...ALLOWED_ORIGIN_HOSTNAMES],
    resourceMetadata: protectedResourceMetadata({
      resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
      authorizationServers: [MCP_AUTH_SERVER_URL],
    }),
    authorization: {
      validator,
      revocation,
      requestDeadlineMs: PROBE_REQUEST_DEADLINE_MS,
      // Injected only when a case declares a cost — otherwise the real-clock default is exercised.
      ...(config.validationCostMs === undefined ? {} : { now: (): number => clockMs }),
      credentials: {
        credentialFor: (request: UpstreamCredentialRequest): Promise<UpstreamCredential> => {
          steps.push('credential');
          credentialRequests.push(request);
          return Promise.resolve({
            accessToken: 'probe-exchanged-credential',
            grantId: request.grant.grantId,
            usableUntilMs: Date.now() + 60_000,
          });
        },
      },
      missingScopeFor: (
        routing: RequestRouting,
        claims: JWTPayload,
        grant: ActiveGrant | undefined
      ): string | undefined => {
        steps.push('scope');
        scopeArgs.push({ routing, claims, grant });
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
    introspections,
    credentialRequests,
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
          method: options.rpcMethod ?? 'tools/list',
          // The required envelope. Without it the SDK refuses at the protocol boundary before
          // dispatch, and the granting case below would read as "reached dispatch" while never
          // having done so.
          params: {
            ...options.rpcParams,
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
  await closeLocalDispatcher();
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
    expect(
      p.steps,
      'offline validation runs first and refuses before everything after it. This sequence is unchanged by live introspection precisely because a credential that did not verify is never presented to the authorization server'
    ).toEqual(['validate']);
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
    expect(
      p.steps,
      'validation, then live introspection, then scope — and dispatch never. The grant is checked BEFORE the scope verdict, because a revoked grant must not reach a step that could consult or mint an upstream credential'
    ).toEqual(['validate', 'introspect', 'scope']);
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
      'the whole realised order, in one assertion: offline validation, then LIVE grant introspection, then the scope check, then dispatch'
    ).toEqual(['validate', 'introspect', 'scope', 'dispatch']);
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
    expect(p.steps, 'the fault must not fall through to dispatch').toEqual([
      'validate',
      'introspect',
      'scope',
    ]);
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
    expect(p.steps, 'and still no dispatch').toEqual(['validate', 'introspect', 'scope']);
    expect(p.reports, 'nothing was reported, because there was nowhere to report it').toEqual([]);
  });

  /** The granting path with no reporter, so the case above is not the only thing exercising it. */
  it('serves a request with no error reporter attached', async () => {
    const p = await start({ validator: 'accepts', omitOnError: true });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.rpcId, 'reached the dispatcher').toBe(1);
    expect(p.steps).toEqual(['validate', 'introspect', 'scope', 'dispatch']);
  });
});

/**
 * Fall-through is unreachable from the security suite (real tokens hit enumerated arms only).
 * Exact equality on the report list — both codes are `unauthorized.`-prefixed, so containment
 * would let them collapse.
 */
describe('the classifier fall-through', () => {
  it('reports a failure outside every enumerated shape as unclassified', async () => {
    const p = await start({
      validator: 'rejects',
      validatorRejectsWith: new RangeError('a shape the classifier has never been taught'),
    });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.status).toBe(401);
    expect(p.reports).toEqual(['unauthorized.unclassified']);
  });

  it('reports an enumerated credential shape as token_rejected, which is a different code', async () => {
    const p = await start({
      validator: 'rejects',
      validatorRejectsWith: new errors.JWTInvalid('a shape the classifier does know'),
    });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.status).toBe(401);
    expect(p.reports).toEqual(['unauthorized.token_rejected']);
  });
});

/** Extract `resource_metadata` and compare with `toBe` — `toContain` passes on a suffix drift. */
function pointerIn(challenge: string | undefined): string | undefined {
  return /resource_metadata="([^"]*)"/.exec(challenge ?? '')?.[1];
}

/**
 * Introspection → wire. Authenticated `active: false` is the only 401; everything else is
 * retryable (401 would refresh-loop against a down component). Assert status, not challenge alone.
 */
describe('what an introspection outcome does to the response', () => {
  it('maps an inactive grant to 401 with a challenge naming the metadata document', async () => {
    const p = await start({ validator: 'accepts', revocation: 'inactive' });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      response.status,
      'an authenticated, explicit active:false is the ONE introspection outcome that maps to 401 — the credential is real and the authority behind it is gone, which is precisely what reauthorizing fixes'
    ).toBe(401);
    expect(response.challenge, 'a 401 from /mcp carries a Bearer challenge').toMatch(/^Bearer\b/);
    expect(
      pointerIn(response.challenge),
      'and the challenge names the RFC 9728 document exactly, so a conformant client can start the connect flow rather than discarding a pointer it cannot match'
    ).toBe(RESOURCE_METADATA_URL);
    expect(
      response.challenge,
      'this is an authentication outcome, not a scope one: naming insufficient_scope would send the client to request scopes it already holds'
    ).not.toContain('insufficient_scope');
    expect(
      p.steps,
      'refused at introspection: the scope check and dispatch are both after it and neither may run'
    ).toEqual(['validate', 'introspect']);
  });

  it('maps an unestablished result to 503, never to 401', async () => {
    const p = await start({ validator: 'accepts', revocation: 'unestablished' });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      response.status,
      'the same status the key-set failure already answers: the component that would authorize this request could not be asked, which is an outage rather than a verdict about the credential'
    ).toBe(503);
    expect(
      response.status,
      'a 401 here loops every client through refresh-and-retry against a backend that is already down'
    ).not.toBe(401);
    expect(
      response.challenge,
      'and no Bearer challenge, which is the header that starts that loop'
    ).toBeUndefined();
    expect(p.steps, 'still refused before scope and before dispatch').toEqual([
      'validate',
      'introspect',
    ]);
  });

  /** Fail closed on an unknown taxonomy shape — never fall through to dispatch. */
  it('closes the request when the checker throws something outside the taxonomy', async () => {
    const p = await start({ validator: 'accepts', revocation: 'faults' });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      response.status,
      'an unrecognised fault is still an unestablished grant, so it denies rather than serves'
    ).toBeGreaterThanOrEqual(500);
    expect(
      response.status,
      'and it is not an authentication verdict: nothing about the credential was established'
    ).not.toBe(401);
    expect(response.challenge).toBeUndefined();
    expect(p.steps, 'the fault must not fall through to the scope check or to dispatch').toEqual([
      'validate',
      'introspect',
    ]);
    expect(p.steps).not.toContain('dispatch');
  });
});

/**
 * No exemption and no positive-result cache. `tools/list` is the tempting skip — assert it too.
 */
describe('live introspection has no exemption and is never cached by the transport', () => {
  /** Rows an implementer might call "too cheap to check". */
  const UNEXEMPT_REQUESTS = [
    {
      label: 'tools/list, which needs no credential downstream',
      methodHeader: 'tools/list',
      nameHeader: undefined,
    },
    {
      label: 'a tools/call whose backing endpoint is public',
      methodHeader: 'tools/call',
      nameHeader: 'nutrition-lookup',
    },
    {
      label: 'a tools/call whose backing endpoint is credentialed',
      methodHeader: 'tools/call',
      nameHeader: 'get-meal-plan',
    },
  ] as const;

  it('introspects exactly once for every request that reaches the boundary', async () => {
    const p = await start({ validator: 'accepts' });

    for (const shape of UNEXEMPT_REQUESTS) {
      // Snapshot before; assert the delta — a cumulative read is satisfied by an earlier iteration.
      const before = p.introspections.length;

      await p.send({
        authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
        methodHeader: shape.methodHeader,
        ...(shape.nameHeader === undefined ? {} : { nameHeader: shape.nameHeader }),
      });

      expect(
        p.introspections.length - before,
        `${shape.label}: exactly one live introspection, from this request rather than from an earlier one`
      ).toBe(1);
    }
  });

  /** `it.each([])` registers nothing and the file still exits 0, so the table needs a floor. */
  it('keeps a floor under the unexempt-request table', () => {
    expect(
      UNEXEMPT_REQUESTS.length,
      'anti-vacuity: emptying this table deletes the no-exemption property in silence'
    ).toBeGreaterThanOrEqual(3);
  });

  it('asks again on the second request rather than reusing the first positive answer', async () => {
    const p = await start({ validator: 'accepts' });

    const first = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });
    const second = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(first.rpcId, 'both requests were served, so neither count is a refusal').toBe(1);
    expect(second.rpcId).toBe(1);
    expect(
      p.introspections,
      'a positive grant result is never cached. Caching one is exactly what would let a grant revoked between these two requests keep working'
    ).toHaveLength(2);
    expect(p.steps).toEqual([
      'validate',
      'introspect',
      'scope',
      'dispatch',
      'validate',
      'introspect',
      'scope',
      'dispatch',
    ]);
  });

  it('presents the token value and a fresh correlation id', async () => {
    const p = await start({ validator: 'accepts' });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });
    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(p.introspections).toHaveLength(2);
    const [first, second] = p.introspections;

    expect(
      first?.token,
      'the token VALUE, extracted from the Bearer credential. An identifier alone is not introspection, and the scheme prefix is not part of the value'
    ).toBe(OPAQUE_CREDENTIAL);

    expect(
      first?.correlationId,
      'generated at the transport boundary, so introspection and every later stage can be tied to one request'
    ).toEqual(expect.any(String));
    expect((first?.correlationId ?? '').length).toBeGreaterThan(0);
    expect(
      second?.correlationId,
      'and generated per request, not once per process: two requests that shared an identifier would be indistinguishable in an audit record'
    ).not.toBe(first?.correlationId);

    // Deadline not asserted here: old `>0 && <= budget` passed double-full-budget wiring. Owned below.
  });

  /**
   * Control: under the named opt-out no `introspect` step — proves sequences above record a real call.
   * Opt-out stays out of the deployed root via `compositionRoot.test.ts`.
   */
  it('records no introspection at all under the named opt-out', async () => {
    const p = await start({ validator: 'accepts', revocation: 'disabled' });

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(response.rpcId, 'the request is still served').toBe(1);
    expect(p.introspections, 'nothing was asked, because nothing was wired').toEqual([]);
    expect(p.steps).toEqual(['validate', 'scope', 'dispatch']);
  });
});

/**
 * One shared request budget. Weaker form `>0 && <= budget` passed double-full-budget wiring
 * (second stage gets exactly the budget). Discriminating shape: fake clock + strict `<` + exact remainder.
 */
describe('the one request budget, shared rather than reissued', () => {
  /** Spent by offline validation before introspection. Any value under the budget. */
  const VALIDATION_COST_MS = 250;

  it('hands introspection what is LEFT of the budget, not a fresh copy of it', async () => {
    const p = await start({ validator: 'accepts', validationCostMs: VALIDATION_COST_MS });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(p.introspections).toHaveLength(1);
    const [only] = p.introspections;

    // Strict `<`: `<=` let the two-full-budgets wiring through (exactly budget satisfies "at most").
    expect(
      only?.deadlineMs,
      'a stage that starts after another has already spent from the budget cannot be given the whole of it. Under a wiring that reissued the full value this reads exactly the budget, which is the defect this assertion exists to catch'
    ).toBeLessThan(PROBE_REQUEST_DEADLINE_MS);

    // Arithmetic, not only direction: any wrong shrink also satisfies `<`.
    expect(
      only?.deadlineMs,
      'what remains is the budget minus what has already been spent, measured from one origin taken before the first spending stage'
    ).toBe(PROBE_REQUEST_DEADLINE_MS - VALIDATION_COST_MS);
  });

  /**
   * Exhaustion: with no budget left, do not attempt introspection (non-positive deadline is worse).
   */
  it.each([
    { label: 'exactly the whole budget', cost: PROBE_REQUEST_DEADLINE_MS },
    { label: 'more than the whole budget', cost: PROBE_REQUEST_DEADLINE_MS + 1 },
  ])('declines to introspect when validation has spent $label', async ({ cost }) => {
    const p = await start({ validator: 'accepts', validationCostMs: cost });

    // Snapshot before; cumulative "did not happen" goes vacuous.
    const before = p.introspections.length;

    const response = await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      response.status,
      'a check that cannot be run is the retryable class, never an authentication verdict: nothing was established about the credential, and a 401 would send the client to refresh a token that is not the problem'
    ).toBe(503);
    expect(
      response.challenge,
      'and no Bearer challenge, which is the header that starts the refresh loop'
    ).toBeUndefined();
    expect(
      p.introspections.length - before,
      'the point of the whole case: no introspection is attempted with a spent budget. Asking with a non-positive deadline either attaches no abort at all or aborts immediately, and both are a request the authorization server has to serve for nothing'
    ).toBe(0);
    expect(
      p.steps,
      'validation ran and nothing after it did — not introspection, not the scope check, not dispatch'
    ).toEqual(['validate']);
    expect(p.steps).not.toContain('dispatch');
  });

  it('keeps a floor under the exhaustion table', () => {
    expect(
      [PROBE_REQUEST_DEADLINE_MS, PROBE_REQUEST_DEADLINE_MS + 1].length,
      'anti-vacuity: the boundary row and the over-spent row are different guards — a check written as `< 0` passes the second and fails the first'
    ).toBe(2);
  });

  /**
   * Granting half: every case above passes if introspection always gets 1ms. Two clocks = two arms.
   */
  it('leaves the whole budget available when nothing has been spent yet', async () => {
    const p = await start({ validator: 'accepts', validationCostMs: 0 });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      p.introspections[0]?.deadlineMs,
      'with a stopped clock nothing has been spent, so the remainder IS the budget. An implementation that always shrinks the deadline — to 1ms, or to nothing — fails here while passing every case above'
    ).toBe(PROBE_REQUEST_DEADLINE_MS);
  });

  it('takes the real clock when none is injected, and still leaves nearly the whole budget', async () => {
    // No validationCostMs → real clock; otherwise a frozen default looks identical in fake-clock cases.
    const p = await start({ validator: 'accepts' });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    const observed = p.introspections[0]?.deadlineMs ?? 0;

    expect(observed, 'a slice with no time in it attaches no usable abort').toBeGreaterThan(0);
    expect(
      observed,
      'no stage may take more than the end-to-end budget, real clock included'
    ).toBeLessThanOrEqual(PROBE_REQUEST_DEADLINE_MS);
    // Slack, not strict: real `Date.now()` delta can be 0ms; strict `<` lives on the fake-clock case.
    expect(
      observed,
      'and an injected fake budget, or a shrink-to-nothing, would not survive this: the real clock spends microseconds here, not seconds'
    ).toBeGreaterThan(PROBE_REQUEST_DEADLINE_MS - 5_000);
  });
});

/**
 * **THE SIX-STEP ORDER, END TO END, WITH SPIES.**
 *
 * Steps 1 to 3 run at the transport, steps 4 to 6 in the registry, and until this ticket the two
 * halves had never been observed in one sequence — which is how a seam owned by three tickets came
 * to be owned by none.
 *
 * Asserted with `toEqual` on an **exact array**. A subsequence or `toContain` assertion is
 * satisfied by a reorder, and a reorder is the entire failure this order exists to prevent: live
 * introspection moved after the credential lookup would let a revoked grant reach a warm cache
 * while every "the step ran" check still passed.
 */
describe('the whole mandatory order, transport and registry in one sequence', () => {
  /**
   * `dispatch` is not a step of the order — it is the SDK boundary the request crosses between
   * step 3 and step 4, and naming it is what makes the two halves visibly one sequence.
   */
  const MANDATORY_ORDER = [
    'validate', // 1. offline, against JWKS
    'introspect', // 2. live grant; no exemption for tools/list or a public endpoint
    'scope', // 3. the frozen map, reading the grant step 2 returned
    'dispatch', // — the SDK boundary
    'credential', // 4. exchanged credential, only for a credentialed backing endpoint
    'audit', // 5. A HOLE. Called in order; what the root supplies stores nothing
    'handler', // 6. the tool itself
  ];

  function registerProbe(
    steps: string[],
    audit: AuditEnqueueEvent[]
  ): (server: McpServer, ctx: McpRequestContext, authorizationFor: AuthorizationLookup) => void {
    return (server, ctx, authorizationFor) => {
      registerTools(server, ctx, {
        confirmations: unavailableConfirmations,
        logConfirmationAnomaly: () => undefined,
        nutrihelpApiBaseUrl: 'https://api.nutrihelp.test',
        authorizationFor,
        resourceMetadataUrl: RESOURCE_METADATA_URL,
        auditEnqueue: (event: AuditEnqueueEvent): Promise<void> => {
          steps.push('audit');
          audit.push(event);
          return Promise.resolve();
        },
        logSecurity: () => undefined,
        logOperational: () => undefined,
        extraTools: [
          {
            ...credentialedProbe,
            handler: (request) => () => {
              steps.push('handler');
              return credentialedProbe.handler(request)();
            },
          },
          {
            ...publicProbe,
            handler: (request) => () => {
              steps.push('handler');
              return publicProbe.handler(request)();
            },
          },
        ],
      });
    };
  }

  it('runs all six in order, for a tool whose backing endpoint is credentialed', async () => {
    const audit: AuditEnqueueEvent[] = [];
    const p = await start({
      validator: 'accepts',
      register: (server, ctx, authorizationFor, steps) => {
        registerProbe(steps, audit)(server, ctx, authorizationFor);
      },
    });

    const response = await p.send({
      authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
      methodHeader: 'tools/call',
      nameHeader: CREDENTIALED_TOOL_NAME,
      rpcMethod: 'tools/call',
      rpcParams: { name: CREDENTIALED_TOOL_NAME, arguments: {} },
    });

    expect(response.rpcCode, 'the call was served rather than refused').toBeUndefined();
    expect(
      p.steps,
      'exact equality: inserting, removing or REORDERING any step fails here, and a reorder is what a position-blind assertion cannot see'
    ).toEqual(MANDATORY_ORDER);
    expect(
      audit.map((event) => [event.tool, event.grantId, typeof event.correlationId]),
      'step 5 was handed opaque references only — never an argument and never the token'
    ).toEqual([[CREDENTIALED_TOOL_NAME, GRANT_A, 'string']]);
  });

  /** Step 4 is per tool. A public backing endpoint must not mint one. */
  it('skips only step 4 for a public backing endpoint, leaving the rest of the order intact', async () => {
    const audit: AuditEnqueueEvent[] = [];
    const p = await start({
      validator: 'accepts',
      register: (server, ctx, authorizationFor, steps) => {
        registerProbe(steps, audit)(server, ctx, authorizationFor);
      },
    });

    await p.send({
      authorization: `Bearer ${OPAQUE_CREDENTIAL}`,
      methodHeader: 'tools/call',
      nameHeader: PUBLIC_TOOL_NAME,
      rpcMethod: 'tools/call',
      rpcParams: { name: PUBLIC_TOOL_NAME, arguments: {} },
    });

    expect(
      p.steps,
      'a public backing endpoint needs no login, so exchange is skipped and NOTHING ELSE moves. The two probes differ on exactly one field, so this comparison is about `backing` rather than about two unrelated tools'
    ).toEqual(['validate', 'introspect', 'scope', 'dispatch', 'audit', 'handler']);
    expect(p.credentialRequests, 'and no credential was minted for it').toHaveLength(0);
    expect(
      nutritionLookupDescriptor.backing,
      'and the one tool this server actually ships is declared public, so the case above describes the shipped path rather than only the fixture'
    ).toBe('public');
  });

  /**
   * STEP 5 IS A HOLE, AND THIS IS WHERE THE SKIP IS REPORTED. It appears in the sequence above
   * because the registry calls it; what the composition root supplies does nothing. A suite that
   * left step 5 out of `MANDATORY_ORDER` would assert five steps while claiming six, and that is
   * exactly the shape that reads as satisfied.
   */
  it('reports that step 5 durably enqueues nothing, because src/audit/logger.ts does not exist', async () => {
    await expect(
      AUDIT_ENQUEUE_NOT_IMPLEMENTED({ tool: 't', correlationId: 'c', grantId: 'g' }),
      'the value the deployed root passes for step 5 accepts the event and stores it nowhere. Per the audit rule a path that skips the durable enqueue is a BYPASS, not a fallback — ticket 34 owns filling it, and this keeps the gap stated rather than assumed'
    ).resolves.toBeUndefined();
  });

  /** The grant introspection returned reaches step 3 as its third argument, not via a hand-off. */
  it('hands the scope step the grant that introspection just established', async () => {
    const p = await start({ validator: 'accepts' });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      p.scopeArgs[0]?.grant,
      'the very object the checker returned. The transport used to discard it, which forced a connection-keyed hand-off that could answer one request from another request live answer'
    ).toBe(ACTIVE_GRANT);
  });

  it('gives the scope step no grant when live introspection was opted out of', async () => {
    const p = await start({ validator: 'accepts', revocation: 'disabled' });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      p.scopeArgs[0]?.grant,
      'a check that never ran must not present as one that passed'
    ).toBeUndefined();
  });
});

/**
 * **THE IDENTITY BINDING ITSELF, AGAINST THE TRANSPORT'S OWN MAP.**
 *
 * The registry suite asserts the same property against a fixture WeakMap, which proves what a
 * WeakMap does rather than what this module built. These cases hold the real lookup — the one
 * `createHttpApp` closes over — and the real `AuthInfo` the SDK handed the factory.
 */
describe('what the transport binds to a request, and what a tool can read off it', () => {
  interface Captured {
    readonly authInfo: AuthInfo;
    readonly lookup: AuthorizationLookup;
    readonly token: string;
  }

  /**
   * Throws rather than returning optionals, so the cases below read as assertions about the
   * binding rather than about whether anything was captured. A transport that set nothing fails
   * here with that sentence instead of quietly passing every `?.` that follows.
   */
  async function capture(): Promise<Captured> {
    const seen: { authInfo?: AuthInfo; lookup?: AuthorizationLookup } = {};
    const p = await start({
      validator: 'accepts',
      register: (_server, ctx, authorizationFor) => {
        if (ctx.authInfo !== undefined) seen.authInfo = ctx.authInfo;
        seen.lookup = authorizationFor;
      },
    });
    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });
    const { authInfo, lookup } = seen;
    if (authInfo === undefined) throw new Error('the transport set no ctx.authInfo at all');
    if (lookup === undefined) throw new Error('the factory was handed no authorization lookup');
    return { authInfo, lookup, token: OPAQUE_CREDENTIAL };
  }

  it('resolves the object it created and MISSES a field-identical copy of it', async () => {
    const { authInfo, lookup } = await capture();

    expect(
      lookup(authInfo),
      'the granting direction: the object the transport created resolves, or every miss below is a miss against an empty map'
    ).toBeDefined();
    expect(
      lookup({ ...authInfo }),
      'a field-for-field copy is NOT a key. An argument or a _meta blob decoded from the request body can carry any fields it likes and can never carry this object identity — which is the whole anti-forgery property, and the reason it is asserted against the transport map rather than a fixture one'
    ).toBeUndefined();
    expect(
      lookup(undefined),
      'and an unauthenticated dispatch resolves nothing rather than the last request answer'
    ).toBeUndefined();
  });

  /**
   * **`AuthInfo.token` carries the DIGEST, and this DEVIATES from the SDK's documented meaning
   * of the field.** It is deliberate: `ctx.authInfo` reaches every tool handler, and one open
   * branch already forwards `ctx.authInfo.token` upstream as a Bearer credential. A digest makes
   * that forwarding fail loudly at the backend instead of working. Do not "fix" this to the SDK
   * convention without removing the forwarding path first.
   */
  it('puts the token DIGEST in AuthInfo.token, never the token itself', async () => {
    const { authInfo, token } = await capture();

    expect(
      authInfo.token,
      'the inbound credential must not be readable by a tool handler. It stays in RequestAuthorization, which only the registry can reach'
    ).not.toBe(token);
    expect(
      authInfo.token,
      'and what is there is the digest the live grant check minted for this exact token, so it is still a stable per-request identifier'
    ).toBe(ACTIVE_GRANT.tokenDigest);
  });

  it('takes clientId and scopes from the GRANT rather than from the JWT claims', async () => {
    const { authInfo } = await capture();

    expect(
      authInfo.clientId,
      'introspection is authoritative. A token minted before a user narrowed a connection still carries the wider claim'
    ).toBe(ACTIVE_GRANT.clientId);
    expect(authInfo.scopes).toEqual([...ACTIVE_GRANT.scopes]);
  });

  it('binds nothing at all when live introspection was opted out of', async () => {
    const seen: { authInfo?: AuthInfo; lookup?: AuthorizationLookup } = {};
    const p = await start({
      validator: 'accepts',
      revocation: 'disabled',
      register: (_server, ctx, authorizationFor) => {
        if (ctx.authInfo !== undefined) seen.authInfo = ctx.authInfo;
        seen.lookup = authorizationFor;
      },
    });

    await p.send({ authorization: `Bearer ${OPAQUE_CREDENTIAL}` });

    expect(
      seen.authInfo,
      'no grant was established, so no identity is minted and every tool refuses at dispatch. The transport-only posture stated rather than faked'
    ).toBeUndefined();
    expect(seen.lookup?.(undefined)).toBeUndefined();
  });
});

/**
 * The credential opt-out, which is the third named sentinel. A transport composed on it must make
 * a credentialed tool **fail**, never proceed with no credential: a public backing
 * endpoint skips exchange, and "the composition opted out" must not become a fourth way to be
 * public. The asymmetry is what makes it dangerous — `tools/list` and every public tool keep
 * working, so a root wired this way reads as healthy.
 */
describe('a transport composed on the credential opt-out', () => {
  it('fails a credentialed tool rather than dispatching it without one', async () => {
    const key = await createTestKeyPair('mcp-signing-key-1');
    const upstream = installUpstreamMock([key]);
    const token = await makeToken({
      key,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: [...ALL_SCOPES],
      sub: USER_A,
      grantId: GRANT_A,
      clientId: CLIENT_ID,
    });
    const server = await startTestServer({
      credentials: { credentialsDisabled: 'transport-tests-only' },
      registerRealTools: true,
      // BOTH probes. With only the credentialed one registered, the control below called a tool
      // nobody had registered — which answers HTTP 200 carrying a JSON-RPC "method not found" —
      // so it passed whether or not a public tool worked, and the asymmetry this case exists to
      // demonstrate was never demonstrated.
      extraTools: [credentialedProbe, publicProbe],
    });

    try {
      const granted = await callTool(server, PUBLIC_TOOL_NAME, {}, token);
      // Asserted as a RESULT, not as a status. `granted.status` is the transport's answer and is
      // 200 for an unknown tool, for a tool error, and for a success alike — a status that matches
      // the hypothesis while an earlier stage produced it.
      const view = expectToolResult(
        granted,
        'control: a PUBLIC tool on this same server still works, which is exactly why an opted-out root reads as healthy'
      );
      expect(view.isError, 'and it succeeded rather than returning a tool error').toBe(false);
      expect(
        view.structured,
        'and it really ran the public probe, with no credential — which is what makes the credentialed refusal below an asymmetry rather than a server that refuses everything'
      ).toEqual({ credentialed: false, grant_id: '' });

      const refused = await callTool(server, CREDENTIALED_TOOL_NAME, {}, token);
      expect(
        refused.rpc?.error ?? (refused.rpc?.result as { isError?: boolean } | undefined)?.isError,
        'the credentialed tool FAILS. Answering it with no credential would make the opt-out a fourth way to be a public endpoint'
      ).toBeTruthy();
    } finally {
      await server.close();
      await upstream.restore();
    }
  });
});

/**
 * **THE DISPATCH-TIME SCOPE RE-CHECK, PROVED LOAD-BEARING OVER THE WIRE.**
 *
 * The transport selects a scope requirement from the `Mcp-Name` ROUTING HEADER. The registry
 * selects one from `tool.name` — the descriptor's own name, fixed at registration. Two different
 * inputs for one decision, and only the second is out of the caller's reach.
 *
 * WHAT DOES NOT REACH HERE, MEASURED RATHER THAN ASSUMED: a header naming a different tool than
 * the body does is refused by the SDK's own protocol rung with HTTP 400 `-32020` before dispatch,
 * and `test/conformance/routingHeaders.test.ts` pins that in all three forms (mismatched name,
 * omitted name, mismatched method). So the re-check is NOT the thing standing between a forged
 * `Mcp-Name` and a tool — do not describe it that way.
 *
 * What it IS standing between is a door check that did not run and the dispatcher. The transport's
 * `missingScopeFor` is an OPTIONAL field, and for the whole of this project's history the
 * composition root did not pass it; omitting it silently turns the pre-dispatch 403 off. These two
 * cases are the same request against the same tools and the same grant, differing in exactly that
 * one field — so the second is about the re-check rather than about a server that refuses
 * everything. Clients also cache tool lists, which is the same argument a step later.
 */
describe('the scope check at the door, and the re-check behind it', () => {
  /** Held by the caller: signed into the token AND returned by introspection. */
  const HELD = SCOPES.mealplanRead;
  /** Required by the tool actually called. Held by nobody in this suite. */
  const NOT_HELD = SCOPES.nutritionRead;

  interface Fixture {
    readonly server: Awaited<ReturnType<typeof startTestServer>>;
    readonly upstream: ReturnType<typeof installUpstreamMock>;
    readonly token: string;
  }

  /** `doorChecks` is the only variable between the two cases below. */
  async function fixture(doorChecks: boolean): Promise<Fixture> {
    const key = await createTestKeyPair('mcp-signing-key-1');
    const upstream = installUpstreamMock([key]);
    const token = await makeToken({
      key,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: [HELD],
      sub: USER_A,
      grantId: GRANT_A,
      clientId: CLIENT_ID,
    });
    // The grant agrees with the token, so a refusal below is about the scope rather than about
    // the grant failing to bind to the claims.
    const grant = forgeActiveGrant({
      grantId: GRANT_A,
      scopes: [HELD],
      subject: USER_A,
      clientId: CLIENT_ID,
    });
    const server = await startTestServer({
      // The real frozen map, not the injected resolver the rest of this file uses: the claim is
      // about which NAME each half reads, and an injected resolver would be answering about a
      // fixture's choice instead.
      ...(doorChecks ? { missingScopeFor: realMissingScopeFor } : {}),
      revocation: { assertGrantActive: (): Promise<ActiveGrant> => Promise.resolve(grant) },
      registerRealTools: true,
    });
    return { server, upstream, token };
  }

  it('refuses at the door when the scope step is wired, before the body is parsed', async () => {
    const { server, upstream, token } = await fixture(true);

    try {
      const response = await callTool(server, 'nutrition_lookup', { food: 'oats' }, token);

      expect(response.status, 'the pre-dispatch 403, from the transport').toBe(403);
      expect(
        response.challenge,
        'naming the scope, so an assistant can ask for step-up. The quoted PARAMETER, not the bare value: a scope name is a prefix of every scope that extends it, so a bare toContain here is satisfied by a challenge naming nutrition:readwrite when the required scope is nutrition:read'
      ).toContain(`scope="${NOT_HELD}"`);
      expect(
        server.registryDenials,
        'and the registry was never reached, so it reported nothing'
      ).toHaveLength(0);
    } finally {
      await server.close();
      await upstream.restore();
    }
  });

  it('refuses at the dispatcher when the door check is not wired at all', async () => {
    const { server, upstream, token } = await fixture(false);

    try {
      const response = await callTool(server, 'nutrition_lookup', { food: 'oats' }, token);

      expect(
        response.status,
        'the door let it through. That is the premise, not a defect: an absent resolver means there is nothing to check, and the transport treats it that way'
      ).not.toBe(403);
      expect(
        server.errors.map((error) => error.message),
        'and the transport reported no scope denial, which is the same statement read from the other side'
      ).not.toContainEqual(expect.stringContaining('insufficient_scope'));

      expect(
        response.rpc?.error ?? (response.rpc?.result as { isError?: boolean } | undefined)?.isError,
        'and the call is refused anyway, by the one check the composition cannot omit: the registry takes its port as a required field, not an optional one'
      ).toBeTruthy();
      expect(
        JSON.stringify(response.rpc ?? {}),
        'and refused AS A SCOPE FAILURE. The assertion above is satisfied by any failure at all — a crash, a timeout, a tool that was never registered — so on its own it says only that something went wrong. This names the class the model was told about; the registryDenials assertion below names the class the operator was told about'
      ).toContain('The granted scopes do not cover this operation.');
      expect(
        server.credentialRequests,
        'refused BEFORE step 4, as the mandatory order requires'
      ).toHaveLength(0);
      expect(
        server.registryDenials,
        'and the refusal is REPORTED, with the tool it was about and the scopes the grant actually carried'
      ).toMatchObject([
        {
          class: 'insufficient_scope',
          requiredScope: NOT_HELD,
          operation: 'nutrition_lookup',
          heldScopes: [HELD],
          userId: USER_A,
          clientId: CLIENT_ID,
          grantId: GRANT_A,
        },
      ]);
    } finally {
      await server.close();
      await upstream.restore();
    }
  });
});
