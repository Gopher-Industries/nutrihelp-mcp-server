/**
 * Live grant introspection (RFC 7662), on every request including `tools/list`.
 * Offline JWKS verify cannot see a deleted connection; only a live ask makes disconnect real.
 * Split that must not collapse:
 *   - authenticated `active: false` is the only "not authorized";
 *   - unreachable / timeout / 5xx / malformed is a retryable upstream failure (not 401).
 */

import { createHash, type KeyObject } from 'node:crypto';
import { McpError, classifyRequestFailure, type RequestFailureKind } from '../errors.ts';
import { postFormWithoutCredential } from '../upstream/client.ts';
import { parseScopeList } from './scopes.ts';
import { CLIENT_ASSERTION_TYPE, clientAssertion, subjectTokenDigest } from './upstreamToken.ts';

/** Log-side endpoint class. Never the path: a path in a log payload is still a path. */
const ENDPOINT_CLASS = 'authorization_server_introspection';

/** Stable log-side identifiers. Not sent to the model, which gets the generic retryable text. */
const ERROR_CODES = {
  unreachable: 'introspection_unreachable',
  status: 'introspection_status',
  malformed: 'introspection_malformed',
  /** Own credential could not be built: configuration fault, not the network. */
  assertion: 'introspection_assertion_unbuildable',
  /** Egress door refused it. Not `unreachable`: neither clears on retry. */
  request: 'introspection_request_unbuildable',
  /** Request-budget slice ran out before the issuer answered. */
  timeout: 'introspection_timeout',
} as const;

/**
 * Shared classifier, own codes. A code naming an endpoint is what tells an operator which call
 * never answered; one shared set would say "introspection" when an exchange failed.
 */
const FAILURE_ERROR_CODES: Readonly<Record<RequestFailureKind, string>> = {
  timeout: ERROR_CODES.timeout,
  unusable_request: ERROR_CODES.request,
  unreachable: ERROR_CODES.unreachable,
};

/** Not exported, and that is the mechanism: no other module can name it, so none can forge one. */
declare const activeGrantBrand: unique symbol;

/**
 * Fields the authorization server returns only when the grant is active.
 *
 * **Branded**, so a function taking one cannot be called without a value this module produced —
 * and it produces one only after a live check answered `active: true`. Forging one still needs an
 * `as unknown as` double cast, visible in review; that is the contract, not a gap in it.
 *
 * **`tokenDigest` is the other half, and it is why the brand alone was not enough.** The brand
 * says a check RAN, not *which token* it ran for: the grant for token B paired with subject token
 * A typechecked, as did one grant held for the whole process. Consumers refuse a mismatch.
 *
 * ⚠️ Still **no freshness claim** — there is no timestamp. What bounds that today is that a grant
 * is minted per request and discarded with it.
 */
export interface ActiveGrant {
  readonly grantId: string;
  readonly scopes: readonly string[];
  readonly subject: string;
  readonly clientId: string;
  /**
   * Digest of the token this check ran against; present at runtime, unlike the brand. The digest
   * and never the token — this outlives the request in a caller's cache key.
   */
  readonly tokenDigest: string;
  /** Type-level only. Never present at runtime and never read. */
  readonly [activeGrantBrand]: true;
}

/** The one place the brand is applied, so "who can mint one" is a single readable line. */
function mintActiveGrant(fields: Omit<ActiveGrant, typeof activeGrantBrand>): ActiveGrant {
  return fields as ActiveGrant;
}

export interface RevocationCheckerOptions {
  /** Absolute URL of `POST /api/oauth/introspect`. */
  readonly introspectionUrl: string;
  /** Registered client id for the assertion. No default or derivation. Not the resource id. */
  readonly clientId: string;
  readonly clientAssertionKey: KeyObject;
  /** `WWW-Authenticate` challenge when the grant is gone. */
  readonly resourceMetadataUrl: string;
  /** How long an `active: false` may be reused, ms; 0 disables. Can refuse faster, never permit. */
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

/** The token travels in the body, so `http:` would publish a live credential. */
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

export function createRevocationChecker(options: RevocationCheckerOptions): RevocationChecker {
  const introspectionUrl = requireHttpsUrl(options.introspectionUrl);

  /**
   * Negative answers only. No positive counterpart, deliberately: a cached "active" is exactly
   * what would let a revoked grant keep working.
   */
  const inactiveUntil = new Map<string, number>();

  /**
   * Keyed by digest, never by the token: this map outlives the request, and the digest answers
   * "same token?" just as well.
   */
  function cacheKey(token: string): string {
    return createHash('sha256').update(token).digest('base64url');
  }

  /**
   * On write: evicting only when the same token returns never reclaims an entry for a token seen
   * once, and that is the common case. Without this the map only grows.
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
   * Every path that reaches a RESPONSE resolves here. Two unestablished paths deliberately do not:
   * the assertion could not be built, and the request was never answered — both already converted
   * above. Checking that none of the four returns a decision means reading three places.
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

    // `readActive` yields a boolean only for a record, so `payload` is one. Narrowed rather than
    // re-tested: a defensive ternary here can never take its else arm, and an unreachable branch
    // is an uncovered branch that reads like a guard.
    return { active, record: payload as Record<string, unknown> };
  }

  async function assertGrantActive(request: IntrospectionRequest): Promise<ActiveGrant> {
    const startedAt = options.now();

    refuseIfCachedInactive(request.token, request.correlationId, startedAt);

    // A key that cannot sign, or a client id nobody supplied. Fails closed either way, but a raw
    // TypeError escaping the authorization path is one the transport's class-based mapping does
    // not recognise, so it is converted; the distinct code says this was ours, not the network.
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
      // Three causes, three records. Folded together they would tell a client to retry a fault
      // that never clears, or an operator that a timeout happened when nothing timed out.
      const kind = classifyRequestFailure(cause);
      throw unavailable(
        request.correlationId,
        FAILURE_ERROR_CODES[kind],
        kind,
        options.now() - startedAt
      );
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

    // Active. Deliberately not cached, in either direction. The digest binds this answer to the
    // token it was asked about, so a consumer cannot pair it with a different one.
    return mintActiveGrant({
      ...identity,
      // Through the scope module's rule, not a second copy of it: this one and that one were
      // byte-identical, and ticket 49's branch already carries a wider split.
      scopes: parseScopeList(record.scope),
      tokenDigest: subjectTokenDigest(request.token),
    });
  }

  return { assertGrantActive };
}
