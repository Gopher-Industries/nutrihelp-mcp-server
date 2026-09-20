/**
 * This server's own credential at the authorization server: `private_key_jwt`, the RFC 8693
 * exchange, and the in-process cache of what it returns.
 *
 * The inbound token leaves this process exactly once per exchange, to the issuer that signed it,
 * in a body carrying no `Authorization` header. Identity is derived from it by the issuer, never
 * sent as a parameter.
 */

import { createHash, type KeyObject } from 'node:crypto';
import { SignJWT } from 'jose';
import { McpError, classifyRequestFailure, type RequestFailureKind } from '../errors.ts';
import { postFormWithoutCredential } from '../upstream/client.ts';
import type { ActiveGrant } from './revocation.ts';

/**
 * Pinned per key type, never negotiated; absent types are refused. `rsa-pss` is deliberately
 * absent — Node cannot sign it here, so a row would name an algorithm that can never sign.
 *
 * RECORDED, NOT FIXED: `ed25519` yields `EdDSA`, which the authorization server's allowlist
 * accepts but its verifier cannot check. An Ed25519 client key boots clean then fails every
 * request, reading as a deregistered client. Dropping the row would refuse it at startup instead
 * — a decision about both sides, and nobody owns it.
 */
const ALGORITHM_BY_KEY_TYPE: Readonly<Record<string, string>> = {
  rsa: 'RS256',
  ec: 'ES256',
  ed25519: 'EdDSA',
};

/** Short because replayable within its window; long enough for clock skew. */
export const CLIENT_ASSERTION_LIFETIME_SECONDS = 60;

/** RFC 7521. The value the endpoint expects alongside `client_assertion`. */
export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export interface ClientAssertionRequest {
  /** This server's private key. Never logged, never serialised. */
  readonly key: KeyObject;
  /** Registered client id. Required, no fallback. Not the resource id: separate registrations. */
  readonly clientId: string;
  /** Who must accept it: the endpoint being called. Introspection and exchange may differ. */
  readonly audience: string;
  /** Injected so expiry is testable without waiting. `undefined` takes the real clock. */
  readonly now: Date | undefined;
  /** Injected so replay assertions can pin it. `undefined` mints one. */
  readonly jti: string | undefined;
}

/** Blank is the shape an invented default arrives in, so it is refused loudly. */
function requireNonBlank(value: string, what: string): string {
  const trimmed = value.trim();
  if (trimmed === '') {
    throw new TypeError(
      `${what} must be a non-empty value. It is not defaulted and must not be derived from the ` +
        'resource identifier: they are separate registrations at the authorization server.'
    );
  }
  return trimmed;
}

function algorithmFor(key: KeyObject): string {
  const keyType = key.asymmetricKeyType;
  if (keyType === undefined) {
    throw new TypeError(
      'The client assertion key must be asymmetric. A symmetric secret would mean sharing a ' +
        'secret with the authorization server rather than proving possession of a key.'
    );
  }
  const algorithm = ALGORITHM_BY_KEY_TYPE[keyType];
  if (algorithm === undefined) {
    throw new TypeError(
      `No signing algorithm is pinned for key type "${keyType}". Add one deliberately, with a ` +
        'test that it can actually sign, rather than letting the key select it.'
    );
  }
  return algorithm;
}

/**
 * Build a `private_key_jwt` client assertion (RFC 7523).
 * `iss` and `sub` are both the client id: required by the spec, not a copy-paste.
 */
export async function clientAssertion(request: ClientAssertionRequest): Promise<string> {
  const clientId = requireNonBlank(request.clientId, 'The client assertion clientId');
  const audience = requireNonBlank(request.audience, 'The client assertion audience');
  const algorithm = algorithmFor(request.key);

  const issuedAt = Math.floor((request.now?.getTime() ?? Date.now()) / 1000);

  return new SignJWT({})
    .setProtectedHeader({ alg: algorithm, typ: 'JWT' })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setJti(request.jti ?? crypto.randomUUID())
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + CLIENT_ASSERTION_LIFETIME_SECONDS)
    .sign(request.key);
}

/* ---- RFC 8693 token exchange ---------------------------------------------------------------- */

/** RFC 8693. Matched exactly by the endpoint; a paraphrase is a rejected request. */
export const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

/** RFC 8693. States what the subject token **is**, not what is asked for in return. */
export const SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

/**
 * How long a credential is reused, in seconds, whatever the issuer says. A longer `expires_in` is
 * the issuer's business; reusing it longer is ours, and this number is the blast radius.
 */
const MAX_CREDENTIAL_LIFETIME_SECONDS = 120;

/**
 * Taken off the window so a credential is never reused with nothing left in it: the upstream call
 * still has to travel, and one expiring in flight fails as a backend auth error, which is the
 * least diagnosable shape available.
 */
const EXPIRY_SAFETY_MARGIN_MS = 10_000;

/**
 * Hard ceiling, which the negative grant cache deliberately lacks: that map holds refusals, this
 * one holds **live bearer credentials**. On overflow nothing is inserted rather than something
 * evicted — a miss costs one exchange and is safe; an unbounded map of live credentials is not.
 */
export const MAX_CACHED_CREDENTIALS = 1000;

/** Log-side endpoint class. Never the path: a path in a log payload is still a path. */
const ENDPOINT_CLASS = 'authorization_server_token_exchange';

/** Stable log-side identifiers. Not sent to the model, which gets the generic retryable text. */
const ERROR_CODES = {
  unreachable: 'exchange_unreachable',
  timeout: 'exchange_timeout',
  /** Egress door refused it (unusable deadline or identity guard). Never clears on retry. */
  request: 'exchange_request_unbuildable',
  /** Own credential could not be built: configuration fault, not the network. */
  assertion: 'exchange_assertion_unbuildable',
  /** Refused with a status this module has no sharper reading of. */
  status: 'exchange_status',
  /** Answered 2xx with something that is not a credential. */
  malformed: 'exchange_malformed',
  /** **Our** client assertion was refused. No user can fix this one. */
  clientRejected: 'exchange_client_credential_rejected',
  /** The subject token was refused: the grant went inactive between the live check and here. */
  grantRejected: 'exchange_subject_token_rejected',
  /** The issuer handed back the subject token as the credential. Refused, never forwarded. */
  echoed: 'exchange_echoed_subject_token',
  /** The grant presented was checked for some other token. A caller fault, failed closed. */
  mismatch: 'exchange_grant_token_mismatch',
} as const;

/**
 * Shared classifier, endpoint-specific codes. One shared set of code strings would tell an
 * operator an introspection timed out when an exchange did.
 */
const FAILURE_ERROR_CODES: Readonly<Record<RequestFailureKind, string>> = {
  timeout: ERROR_CODES.timeout,
  unusable_request: ERROR_CODES.request,
  unreachable: ERROR_CODES.unreachable,
};

/**
 * Empty, and the request omits `scope` entirely, so the issuer mints the grant's own set. Still in
 * the cache key: the day a tool asks for a narrower set, a key without it serves it the wide one.
 */
const REQUESTED_SCOPES: readonly string[] = [];

/**
 * Identifies a subject token without holding one. **One hand-written statement of the algorithm**,
 * used by both sides: the live grant check mints it, this module compares and keys its cache on
 * it. A second copy would drift silently, since a mismatch presents as a cache that never hits.
 *
 * `revocation.ts` imports this rather than the reverse — it already imports from here at runtime,
 * so this direction adds no cycle, and the type travels back as an erased `import type`.
 */
export function subjectTokenDigest(token: string): string {
  return createHash('sha256').update(token).digest('base64url');
}

/** Sorted and space-joined, so two orderings of one set are one key rather than two. */
function scopeKey(scopes: readonly string[]): string {
  return [...scopes].sort().join(' ');
}

const REQUESTED_SCOPE_KEY = scopeKey(REQUESTED_SCOPES);

export interface ExchangeOperationalEvent {
  readonly event: 'token_exchange_failed';
  readonly errorCode: string;
  readonly statusClass: string;
  readonly endpointClass: string;
  readonly correlationId: string;
  readonly latencyMs: number;
}

export interface ExchangeSecurityEvent {
  /**
   * Separated because they need different readers: a rejected client credential is ours and no
   * user action reaches it, while the other three are about the grant or the token.
   */
  readonly event:
    | 'token_exchange_client_credential_rejected'
    | 'token_exchange_subject_token_rejected'
    | 'token_exchange_echoed_subject_token'
    | 'upstream_credential_grant_token_mismatch';
  readonly correlationId: string;
  /** Opaque grant reference. Never the token, in either direction. */
  readonly grantId: string;
}

export interface ExchangeOptions {
  /** Absolute URL of `POST /api/oauth/token`. Must differ from the introspection endpoint. */
  readonly tokenEndpointUrl: string;
  /** Registered client id, threaded into the assertion. No default and no derivation. */
  readonly clientId: string;
  readonly clientAssertionKey: KeyObject;
  /** Injected so cache expiry is testable without waiting. */
  readonly now: () => number;
  /** Operational channel: transport and contract failures. */
  readonly logOperational: (event: ExchangeOperationalEvent) => void;
  /** Security channel: a credential refused. A separate record from the operational one. */
  readonly logSecurity: (event: ExchangeSecurityEvent) => void;
}

export interface UpstreamCredentialRequest {
  /** The inbound access token, presented to its own issuer as the subject token. */
  readonly subjectToken: string;
  /**
   * What the live grant check returned **for this request**. The brand is unexported, so a caller
   * that skipped introspection cannot satisfy this parameter; the digest it carries says which
   * token the check ran for, and a mismatch is refused below. The brand alone gave only the first
   * half, which is why both exist.
   */
  readonly grant: ActiveGrant;
  readonly correlationId: string;
  /**
   * Remaining request-budget slice, in ms. Required, no `undefined` hatch: this call takes a slice
   * of the one end-to-end budget, never a fresh full one. Unusable slices are refused, not
   * replaced.
   */
  readonly deadlineMs: number;
}

export interface UpstreamCredential {
  /** The exchanged, backend-audience credential. Never logged and never the subject token. */
  readonly accessToken: string;
  /** The grant it was minted under. A cached entry from another grant is a miss, not a hit. */
  readonly grantId: string;
  /**
   * Epoch ms after which this server stops reusing it, margin already subtracted.
   *
   * **Governs reuse only, and may already be in the past on a fresh credential** — an issuer
   * lifetime at or under the margin leaves nothing to reuse. Reading it as "expired, exchange
   * again" loops forever against such an issuer. Use what you were handed; consult this only when
   * deciding whether to reuse a previous one.
   */
  readonly usableUntilMs: number;
}

export interface UpstreamCredentialProvider {
  /**
   * The cached credential for this grant, or a fresh exchange. **Nothing here maps to 401**: a
   * refusal is our problem or a revocation race, never a signal to refresh the client's token.
   */
  readonly credentialFor: (request: UpstreamCredentialRequest) => Promise<UpstreamCredential>;
}

/**
 * The **subject token travels in this request body**, so a cleartext scheme publishes a live user
 * credential. Guarded on the parameter rather than trusted from composition: no config variable
 * carries this URL, it is derived from one, and a derivation is not a validation.
 */
function requireHttpsUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new TypeError(`The token exchange URL is not a URL: ${value}`);
  }
  if (url.protocol !== 'https:') {
    throw new TypeError(
      'The token exchange URL must be https. The inbound access token is sent in this request ' +
        'body as the subject token, so a cleartext scheme would publish a live credential.'
    );
  }
  return url.href;
}

/** Status family such as `5xx` / `4xx`. Never a status number in a payload. */
function statusClassOf(status: number): string {
  return `${String(Math.floor(status / 100))}xx`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * **Exactly five parameters, and the omissions are decisions.** `scope`, `requested_token_type`,
 * `resource` and `audience` are absent: the issuer refuses any `resource` or `audience` that is
 * not its own backend API audience, and that string is not knowable from this repository.
 */
function exchangeForm(subjectToken: string, assertion: string): Record<string, string> {
  return {
    grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
    subject_token: subjectToken,
    subject_token_type: SUBJECT_TOKEN_TYPE,
    client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: assertion,
  };
}

interface ExchangeResponseFields {
  readonly accessToken: string;
  readonly expiresInSeconds: number;
}

/** Non-empty string or nothing. An empty one is a credential that authenticates as nobody. */
function readAccessToken(payload: Record<string, unknown>): string | undefined {
  const value = payload.access_token;
  return typeof value === 'string' && value !== '' ? value : undefined;
}

/**
 * Finite and positive, or nothing. A string `"120"`, `0`, a negative or `Infinity` are malformed
 * rather than defaultable: each would pick a lifetime nobody granted, and the safe-looking
 * direction — treat it as expired — hides a contract break behind an exchange per request.
 */
function readExpiresIn(payload: Record<string, unknown>): number | undefined {
  const value = payload.expires_in;
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return undefined;
  return value;
}

/**
 * Present and not Bearer is refused; **absent is accepted, deliberately.** Nothing here consumes
 * `token_type`, so requiring it would refuse a working exchange over a value that changes no
 * behaviour. The two fields this module does consume are both required above.
 */
function tokenTypeAcceptable(payload: Record<string, unknown>): boolean {
  const value = payload.token_type;
  if (value === undefined) return true;
  return typeof value === 'string' && value.toLowerCase() === 'bearer';
}

function readExchangeResponse(payload: unknown): ExchangeResponseFields | undefined {
  if (!isRecord(payload)) return undefined;
  if (!tokenTypeAcceptable(payload)) return undefined;
  const accessToken = readAccessToken(payload);
  const expiresInSeconds = readExpiresIn(payload);
  if (accessToken === undefined || expiresInSeconds === undefined) return undefined;
  return { accessToken, expiresInSeconds };
}

/**
 * Best effort. A body that will not parse yields nothing, which is correct: an unreadable refusal
 * is not evidence about which credential was refused.
 */
async function readErrorCode(response: Response): Promise<string | undefined> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return undefined;
  }
  if (!isRecord(payload)) return undefined;
  const error = payload.error;
  return typeof error === 'string' ? error : undefined;
}

type RefusalKind = 'client_credential' | 'subject_token' | 'other';

/**
 * Which credential the endpoint refused. `invalid_client` is **ours** — key, client id or
 * assertion audience — and no user action reaches it. `invalid_grant` is the **subject token**:
 * the grant went inactive between the live check and this call. It is deliberately **not** written
 * into the grant negative cache, which belongs to the module that asks the authoritative question;
 * a refusal inferred here is one endpoint's answer to a different question.
 *
 * **The order of these three lines is the contract.** A stated code always wins; the status is
 * consulted only when none was readable. Reading the status first files a `401
 * {"error":"invalid_grant"}` against our own credential — right class, wrong security record, and
 * an operator sent to look at a key that is fine. The fallback still earns its place, because a
 * **bare** 401 is that same client-credential finding with the body missing.
 */
function classifyRefusal(status: number, errorCode: string | undefined): RefusalKind {
  if (errorCode === 'invalid_client') return 'client_credential';
  if (errorCode === 'invalid_grant') return 'subject_token';
  if (status === 401) return 'client_credential';
  return 'other';
}

interface ExchangeContext {
  readonly options: ExchangeOptions;
  readonly request: UpstreamCredentialRequest;
  /** Already guarded and normalised. */
  readonly url: string;
  readonly startedAt: number;
}

function unavailable(ctx: ExchangeContext, errorCode: string, statusClass: string): McpError {
  const latencyMs = ctx.options.now() - ctx.startedAt;
  ctx.options.logOperational({
    event: 'token_exchange_failed',
    errorCode,
    statusClass,
    endpointClass: ENDPOINT_CLASS,
    correlationId: ctx.request.correlationId,
    latencyMs,
  });
  return new McpError({
    class: 'upstream_failure',
    statusClass,
    errorCode,
    endpointClass: ENDPOINT_CLASS,
    correlationId: ctx.request.correlationId,
    latencyMs,
  });
}

function noteSecurity(ctx: ExchangeContext, event: ExchangeSecurityEvent['event']): void {
  ctx.options.logSecurity({
    event,
    correlationId: ctx.request.correlationId,
    grantId: ctx.request.grant.grantId,
  });
}

/** Every refusal is the retryable class to the model. The channel it also lands in differs. */
async function refusalFor(ctx: ExchangeContext, response: Response): Promise<McpError> {
  const statusClass = statusClassOf(response.status);
  const kind = classifyRefusal(response.status, await readErrorCode(response));

  if (kind === 'client_credential') {
    noteSecurity(ctx, 'token_exchange_client_credential_rejected');
    return unavailable(ctx, ERROR_CODES.clientRejected, statusClass);
  }
  if (kind === 'subject_token') {
    noteSecurity(ctx, 'token_exchange_subject_token_rejected');
    return unavailable(ctx, ERROR_CODES.grantRejected, statusClass);
  }
  return unavailable(ctx, ERROR_CODES.status, statusClass);
}

/**
 * The assertion's `aud` is this endpoint and nothing else. The authorization server accepts an
 * assertion only at the endpoint it names, so the introspection URL presented here is refused —
 * which is why the two URLs must never collapse into one configured value.
 */
async function buildAssertion(ctx: ExchangeContext): Promise<string> {
  try {
    return await clientAssertion({
      key: ctx.options.clientAssertionKey,
      clientId: ctx.options.clientId,
      audience: ctx.url,
      now: new Date(ctx.startedAt),
      jti: undefined,
    });
  } catch {
    // A key that cannot sign, or a client id nobody supplied. Converted rather than escaping as a
    // raw TypeError the transport's class-based mapping does not recognise; the distinct code is
    // what tells an operator this was our credential and not the network.
    throw unavailable(ctx, ERROR_CODES.assertion, 'unusable_credential');
  }
}

/**
 * `redirect: 'error'`, and no trailing slash: the endpoint publishes no trailing-slash redirect,
 * and its rate-limit carve-out matches the path by exact equality, so a near-miss lands in the
 * global bucket instead of the one sized for this call.
 */
async function postExchange(ctx: ExchangeContext, assertion: string): Promise<Response> {
  try {
    return await postFormWithoutCredential({
      url: ctx.url,
      form: exchangeForm(ctx.request.subjectToken, assertion),
      deadlineMs: ctx.request.deadlineMs,
      correlationId: ctx.request.correlationId,
      redirect: 'error',
    });
  } catch (cause) {
    const kind = classifyRequestFailure(cause);
    throw unavailable(ctx, FAILURE_ERROR_CODES[kind], kind);
  }
}

/** Lifetime runs from when the request **started**: the issuer's clock started before ours. */
async function readCredential(
  ctx: ExchangeContext,
  response: Response
): Promise<UpstreamCredential> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    payload = undefined;
  }

  const fields = readExchangeResponse(payload);
  if (fields === undefined) {
    throw unavailable(ctx, ERROR_CODES.malformed, statusClassOf(response.status));
  }

  // A 2xx is not consent to hold whatever came back. An echoed subject token accepted here is
  // the inbound token attached to a data-backend request by the first caller that uses it — the
  // front door. Equality, NOT containment: a substring rule would reject legitimate credentials
  // for a property that is not the hazard. Checkable only here, the last point holding both.
  if (fields.accessToken === ctx.request.subjectToken) {
    noteSecurity(ctx, 'token_exchange_echoed_subject_token');
    throw unavailable(ctx, ERROR_CODES.echoed, 'echoed_subject_token');
  }

  const lifetimeMs =
    Math.min(fields.expiresInSeconds, MAX_CREDENTIAL_LIFETIME_SECONDS) * 1000 -
    EXPIRY_SAFETY_MARGIN_MS;

  return {
    accessToken: fields.accessToken,
    grantId: ctx.request.grant.grantId,
    usableUntilMs: ctx.startedAt + lifetimeMs,
  };
}

/**
 * The brand proves a live check RAN; the digest proves **which token** it ran for. Without this
 * line the two are independent: the grant for token B paired with subject token A typechecks, as
 * does one grant held for the process lifetime. Runtime, not just types — a compile-time guard is
 * absent from a running server. Recorded on the **security** channel, because presenting a grant
 * never checked for this token is the confused-deputy shape whatever caused it.
 */
function assertGrantMatchesToken(ctx: ExchangeContext): void {
  if (ctx.request.grant.tokenDigest === subjectTokenDigest(ctx.request.subjectToken)) return;
  noteSecurity(ctx, 'upstream_credential_grant_token_mismatch');
  throw unavailable(ctx, ERROR_CODES.mismatch, 'grant_token_mismatch');
}

/**
 * One exchange, no cache. Exported so the wire contract can be driven directly.
 *
 * **Here a bad endpoint URL escapes as a raw `TypeError`**, unlike every other failure, which
 * is converted. The provider guards the URL at construction so production cannot reach it.
 */
export async function exchangeUpstreamCredential(
  options: ExchangeOptions,
  request: UpstreamCredentialRequest
): Promise<UpstreamCredential> {
  const ctx: ExchangeContext = {
    options,
    request,
    url: requireHttpsUrl(options.tokenEndpointUrl),
    startedAt: options.now(),
  };

  assertGrantMatchesToken(ctx);

  const response = await postExchange(ctx, await buildAssertion(ctx));
  if (!response.ok) throw await refusalFor(ctx, response);
  return readCredential(ctx, response);
}

/**
 * Per-process by adopted design, not by shortcut: an entry is unusable until **this** request's
 * live grant check has succeeded, so a shared store would buy nothing and would put live bearer
 * credentials where a second process can read them.
 */
export function createUpstreamCredentialProvider(
  options: ExchangeOptions
): UpstreamCredentialProvider {
  const tokenEndpointUrl = requireHttpsUrl(options.tokenEndpointUrl);
  const exchangeOptions: ExchangeOptions = { ...options, tokenEndpointUrl };

  /**
   * Keyed by digest, never by the token: this map outlives the request, and a raw token in it
   * would keep a second live credential in memory per entry. The digest comes from the **grant**,
   * not recomputed beside it — they are proved equal a line earlier, so one statement of "which
   * token is this" rather than two that can drift. It identifies the token the way a `jti` would.
   */
  const credentials = new Map<string, UpstreamCredential>();

  /** Newline separator: neither half can contain one, so no two pairs collide by concatenation. */
  function cacheKey(grant: ActiveGrant): string {
    return `${grant.tokenDigest}\n${REQUESTED_SCOPE_KEY}`;
  }

  /**
   * On write: evicting only when the same token returns never reclaims an entry for a token seen
   * once, and that is the common case.
   */
  function evictExpired(asOf: number): void {
    for (const [key, entry] of credentials) {
      if (entry.usableUntilMs <= asOf) credentials.delete(key);
    }
  }

  /**
   * Inside its window **and** minted under the grant just checked. The same token under a new
   * grant is a new authorization; the old credential would carry the previous grant's scope and
   * role past the check meant to gate them.
   */
  function cached(key: string, grantId: string, asOf: number): UpstreamCredential | undefined {
    const entry = credentials.get(key);
    if (entry === undefined) return undefined;
    if (entry.usableUntilMs <= asOf) {
      credentials.delete(key);
      return undefined;
    }
    return entry.grantId === grantId ? entry : undefined;
  }

  /** Refuses to insert rather than evicting a live entry: a miss costs one exchange. */
  function store(key: string, credential: UpstreamCredential, asOf: number): void {
    evictExpired(asOf);
    if (credential.usableUntilMs <= asOf) return;
    if (!credentials.has(key) && credentials.size >= MAX_CACHED_CREDENTIALS) return;
    credentials.set(key, credential);
  }

  async function credentialFor(request: UpstreamCredentialRequest): Promise<UpstreamCredential> {
    // Before the cache is even consulted: a mismatched grant must not be able to READ an entry,
    // and checking inside the exchange alone would leave a cache hit as the way around it.
    assertGrantMatchesToken({
      options: exchangeOptions,
      request,
      url: tokenEndpointUrl,
      startedAt: options.now(),
    });

    const key = cacheKey(request.grant);
    const hit = cached(key, request.grant.grantId, options.now());
    if (hit !== undefined) return hit;

    const credential = await exchangeUpstreamCredential(exchangeOptions, request);
    store(key, credential, options.now());
    return credential;
  }

  return { credentialFor };
}
