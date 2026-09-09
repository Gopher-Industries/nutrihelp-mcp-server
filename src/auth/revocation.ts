/**
 * Live grant introspection (RFC 7662), on every request including `tools/list`.
 * Offline JWKS verify cannot see a deleted connection; only a live ask makes disconnect real.
 * Split that must not collapse:
 *   - authenticated `active: false` is the only "not authorized";
 *   - unreachable / timeout / 5xx / malformed is a retryable upstream failure (not 401).
 */

import { createHash, type KeyObject } from 'node:crypto';
import { McpError } from '../errors.ts';
import { postFormWithoutCredential } from '../upstream/client.ts';
import { CLIENT_ASSERTION_TYPE, clientAssertion } from './upstreamToken.ts';

/** Log-side endpoint class. Never the path: a path in a log payload is still a path. */
const ENDPOINT_CLASS = 'authorization_server_introspection';

/** Stable log-side identifiers. Not sent to the model, which gets the generic retryable text. */
const ERROR_CODES = {
  unreachable: 'introspection_unreachable',
  status: 'introspection_status',
  malformed: 'introspection_malformed',
  /** Own credential could not be built: configuration fault, not the network. */
  assertion: 'introspection_assertion_unbuildable',
  /**
   * Egress door refused the request (unusable deadline or identity guard). Not `unreachable`:
   * neither clears on retry. Malformed URLs do not land here (`fetch` + `cause`, or
   * `requireHttpsUrl` at construction).
   */
  request: 'introspection_request_unbuildable',
  /** Request-budget slice ran out before the issuer answered. */
  timeout: 'introspection_timeout',
} as const;

/**
 * Why a request never produced a response. Measured on Node v24.19.0; the obvious
 * discriminator is backwards:
 *   - unresolvable host: `TypeError: fetch failed` **with** `cause`;
 *   - spent deadline: `TimeoutError` / `AbortError` (not a `TypeError`);
 *   - egress refusal: `TypeError` with **no** `cause`.
 * Match abort by name; use `cause` to separate undici from our door.
 */
function classifyRequestFailure(cause: unknown): {
  readonly errorCode: string;
  readonly statusClass: string;
} {
  if (cause instanceof Error && (cause.name === 'TimeoutError' || cause.name === 'AbortError')) {
    return { errorCode: ERROR_CODES.timeout, statusClass: 'timeout' };
  }
  if (cause instanceof TypeError && cause.cause === undefined) {
    return { errorCode: ERROR_CODES.request, statusClass: 'unusable_request' };
  }
  return { errorCode: ERROR_CODES.unreachable, statusClass: 'unreachable' };
}

/** Fields the authorization server returns only when the grant is active. */
export interface ActiveGrant {
  readonly grantId: string;
  readonly scopes: readonly string[];
  readonly subject: string;
  readonly clientId: string;
}

export interface RevocationCheckerOptions {
  /** Absolute URL of `POST /api/oauth/introspect`. */
  readonly introspectionUrl: string;
  /**
   * Registered client id, threaded into the assertion. No default or derivation.
   * Parameter (not config) until the client-id gap is settled. Not the resource id.
   */
  readonly clientId: string;
  readonly clientAssertionKey: KeyObject;
  /** `WWW-Authenticate` challenge when the grant is gone. */
  readonly resourceMetadataUrl: string;
  /**
   * How long an `active: false` may be reused, in ms. 0 disables it.
   * Never caches an active answer; can only refuse faster, never permit.
   */
  readonly negativeCacheMaxAgeMs: number;
  /** Injected so cache expiry is testable without waiting. */
  readonly now: () => number;
  /** Operational channel: transport and contract failures. Not a security anomaly. */
  readonly logOperational: (event: OperationalEvent) => void;
  /** Security channel: a dispatch actually denied. A separate record from the operational one. */
  readonly logSecurity: (event: SecurityEvent) => void;
}

export interface OperationalEvent {
  readonly event: 'introspection_failed';
  readonly errorCode: string;
  readonly statusClass: string;
  readonly endpointClass: string;
  readonly correlationId: string;
  readonly latencyMs: number;
}

export interface SecurityEvent {
  readonly event: 'grant_inactive';
  readonly correlationId: string;
  /** Whether this refusal came from the negative cache rather than a fresh answer. */
  readonly fromNegativeCache: boolean;
}

export interface IntrospectionRequest {
  /** The access-token **value**. An identifier alone is not introspection. */
  readonly token: string;
  readonly correlationId: string;
  /**
   * Remaining request-budget slice, in ms. Required: absent attaches no abort signal.
   * Caller computes the slice; this module refuses an unusable one.
   */
  readonly deadlineMs: number;
}

export interface RevocationChecker {
  /** Live grant only. Throws `unauthorized` if inactive; `upstream_failure` if unaskable. */
  readonly assertGrantActive: (request: IntrospectionRequest) => Promise<ActiveGrant>;
}

/** Status family such as `5xx` / `4xx` / `timeout`. Never a status number in a payload. */
function statusClassOf(status: number): string {
  return `${String(Math.floor(status / 100))}xx`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Only a real boolean counts. Missing / string / truthy-looking `active` means unestablished
 * (outage, not a decision). Coercing here turns a malformed response into silent authorization.
 */
function readActive(payload: unknown): boolean | undefined {
  if (!isRecord(payload)) return undefined;
  const active = payload.active;
  return typeof active === 'boolean' ? active : undefined;
}

/**
 * Identity an active answer must carry (`sub`, `client_id`, `grant_id`). Absent or wrong type
 * on an active answer is a contract violation. Do not coerce missing fields to `''`.
 */
function readIdentity(
  payload: Record<string, unknown>
): Pick<ActiveGrant, 'grantId' | 'subject' | 'clientId'> | undefined {
  const grantId = payload.grant_id;
  const subject = payload.sub;
  const clientId = payload.client_id;
  if (typeof grantId !== 'string' || grantId === '') return undefined;
  if (typeof subject !== 'string' || subject === '') return undefined;
  if (typeof clientId !== 'string' || clientId === '') return undefined;
  return { grantId, subject, clientId };
}

/**
 * Token travels in the body, so `http:` would put a live credential on the wire.
 * No config variable for this URL; guard the parameter here.
 */
function requireHttpsUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new TypeError(`The introspection URL is not a URL: ${value}`);
  }
  if (url.protocol !== 'https:') {
    throw new TypeError(
      'The introspection URL must be https. The access token is sent in this request body, so ' +
        'a cleartext scheme would publish a live credential to anyone on the path.'
    );
  }
  return url.href;
}

/** RFC 6749 scope is space-delimited. Absent means no scopes, never "all". */
function readScopes(payload: Record<string, unknown>): readonly string[] {
  const scope = payload.scope;
  if (typeof scope !== 'string') return [];
  return scope.split(' ').filter((entry) => entry !== '');
}

export function createRevocationChecker(options: RevocationCheckerOptions): RevocationChecker {
  const introspectionUrl = requireHttpsUrl(options.introspectionUrl);

  /**
   * Negative answers only, keyed by the digest below rather than the token. An entry is read only
   * while younger than the TTL, and a hit refuses. There is deliberately no positive counterpart,
   * because a cached "active" is exactly what would let a revoked grant keep working.
   */
  const inactiveUntil = new Map<string, number>();

  /**
   * Keyed by digest, never by the token. The map outlives any single request, so holding raw
   * access tokens in it would keep credentials in process memory long past their usefulness for
   * no gain — the digest answers "same token?" just as well.
   */
  function cacheKey(token: string): string {
    return createHash('sha256').update(token).digest('base64url');
  }

  /**
   * Drop everything already expired. Called on write, because the alternative — evicting only
   * when the same token is presented again — never reclaims an entry for a token that is simply
   * never seen twice, and that is the common case. Without it the map only grows.
   */
  function evictExpired(asOf: number): void {
    for (const [key, expiresAt] of inactiveUntil) {
      if (expiresAt <= asOf) inactiveUntil.delete(key);
    }
  }

  function refuse(correlationId: string, reason: string, fromNegativeCache: boolean): McpError {
    options.logSecurity({ event: 'grant_inactive', correlationId, fromNegativeCache });
    return new McpError({
      class: 'unauthorized',
      reason,
      resourceMetadataUrl: options.resourceMetadataUrl,
    });
  }

  function unavailable(
    correlationId: string,
    errorCode: string,
    statusClass: string,
    latencyMs: number
  ): McpError {
    options.logOperational({
      event: 'introspection_failed',
      errorCode,
      statusClass,
      endpointClass: ENDPOINT_CLASS,
      correlationId,
      latencyMs,
    });
    return new McpError({
      class: 'upstream_failure',
      statusClass,
      errorCode,
      endpointClass: ENDPOINT_CLASS,
      correlationId,
      latencyMs,
    });
  }

  /** Refuses from cache, or clears a stale entry. Split out to keep the caller under the bright line. */
  function refuseIfCachedInactive(token: string, correlationId: string, startedAt: number): void {
    const key = cacheKey(token);
    const cachedUntil = inactiveUntil.get(key);
    if (cachedUntil === undefined) return;
    if (cachedUntil > startedAt) {
      throw refuse(correlationId, 'grant previously reported inactive', true);
    }
    inactiveUntil.delete(key);
  }

  /**
   * The response to an explicit boolean, or an upstream failure.
   *
   * Every path that reaches a RESPONSE is resolved here. Two unestablished paths deliberately do
   * not pass through: the assertion could not be built, and the request was refused or never
   * answered — both above, both already converted. Checking that none of the four returns a
   * decision means reading three places, not one.
   */
  async function resolveActive(
    response: Response,
    correlationId: string,
    startedAt: number
  ): Promise<{ readonly active: boolean; readonly record: Record<string, unknown> }> {
    if (!response.ok) {
      throw unavailable(
        correlationId,
        ERROR_CODES.status,
        statusClassOf(response.status),
        options.now() - startedAt
      );
    }

    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      payload = undefined;
    }

    const active = readActive(payload);
    if (active === undefined) {
      throw unavailable(
        correlationId,
        ERROR_CODES.malformed,
        statusClassOf(response.status),
        options.now() - startedAt
      );
    }

    // `readActive` only yields a boolean for a record, so `payload` is one here. Narrowed rather
    // than re-tested: a defensive `isRecord` ternary at this point can never take its else arm,
    // and an unreachable branch is an uncovered branch that reads like a guard.
    return { active, record: payload as Record<string, unknown> };
  }

  async function assertGrantActive(request: IntrospectionRequest): Promise<ActiveGrant> {
    const startedAt = options.now();

    refuseIfCachedInactive(request.token, request.correlationId, startedAt);

    // A key that cannot sign, or a client identifier that was never supplied, throws here. It
    // still fails closed, but a raw TypeError or DOMException escaping the authorization path is
    // one the transport's class-based mapping does not recognise — so it is converted to the
    // retryable class like any other reason the issuer could not be asked. The distinct code is
    // what tells an operator this was our own credential and not the network.
    let assertion: string;
    try {
      assertion = await clientAssertion({
        key: options.clientAssertionKey,
        clientId: options.clientId,
        audience: introspectionUrl,
        now: new Date(startedAt),
        jti: undefined,
      });
    } catch {
      throw unavailable(
        request.correlationId,
        ERROR_CODES.assertion,
        'unusable_credential',
        options.now() - startedAt
      );
    }

    let response: Response;
    try {
      response = await postFormWithoutCredential({
        url: introspectionUrl,
        form: {
          token: request.token,
          token_type_hint: 'access_token',
          client_assertion_type: CLIENT_ASSERTION_TYPE,
          client_assertion: assertion,
        },
        deadlineMs: request.deadlineMs,
        correlationId: request.correlationId,
        redirect: 'error',
      });
    } catch (cause) {
      // Three distinct causes, three records. Folding them together would tell the client to
      // retry a fault that never clears, or tell the operator a timeout happened when nothing
      // timed out. The classifier documents why the shapes are not what they look like.
      const { errorCode, statusClass } = classifyRequestFailure(cause);
      throw unavailable(request.correlationId, errorCode, statusClass, options.now() - startedAt);
    }

    const { active, record } = await resolveActive(response, request.correlationId, startedAt);

    if (!active) {
      if (options.negativeCacheMaxAgeMs > 0) {
        const asOf = options.now();
        evictExpired(asOf);
        inactiveUntil.set(cacheKey(request.token), asOf + options.negativeCacheMaxAgeMs);
      }
      throw refuse(
        request.correlationId,
        'authorization server reported the grant inactive',
        false
      );
    }

    const identity = readIdentity(record);
    if (identity === undefined) {
      throw unavailable(
        request.correlationId,
        ERROR_CODES.malformed,
        'incomplete_identity',
        options.now() - startedAt
      );
    }

    // Active. Deliberately not cached, in either direction.
    return { ...identity, scopes: readScopes(record) };
  }

  return { assertGrantActive };
}
