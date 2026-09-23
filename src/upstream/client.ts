/** The single egress module for NutriHelp HTTP and Render Key Value connections.
 * Supports unauthenticated GET and declared query assembly with identity filtering.
 * Credential attachment and retry with backoff/jitter remain future work.
 * Do not improvise outbound policy in a caller.
 */

import { createClient } from '@redis/client';

/** Inbound correlation id, or a freshly minted id when none was supplied. */
export const CORRELATION_ID_HEADER = 'x-correlation-id';

export interface KeyValueConnection {
  readonly eval: (
    script: string,
    keys: string[],
    args: string[],
    timeoutMs: number
  ) => Promise<unknown>;
  readonly close: () => void;
}

/** The Redis socket stays in the same egress module as HTTP. No offline command queue. */
export async function connectKeyValue(url: string, timeoutMs: number): Promise<KeyValueConnection> {
  assertUsableDeadline(timeoutMs);
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new TypeError('Invalid Key Value configuration');
  }
  if (!['redis:', 'rediss:'].includes(parsed.protocol) || parsed.search || parsed.hash) {
    throw new TypeError('Invalid Key Value configuration');
  }
  let client: ReturnType<typeof createClient>;
  try {
    client = createClient({
      url,
      disableOfflineQueue: true,
      socket: {
        connectTimeout: timeoutMs,
        // Eight retries, capped exponential delay plus jitter; failed commands are never queued.
        reconnectStrategy: (retries) =>
          retries >= 8
            ? false
            : Math.min(100 * 2 ** retries, 2_000) + Math.floor(Math.random() * 100),
      },
    });
  } catch {
    throw new TypeError('Invalid Key Value configuration');
  }
  // Required EventEmitter listener. Command/connect rejections report only a generic failure.
  client.on('error', () => {
    // Individual operations reject. Logging this event would expose the Redis URL or command.
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      client.connect(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error('Key Value connection timed out'));
        }, timeoutMs);
      }),
    ]);
  } catch {
    if (client.isOpen) client.destroy();
    throw new Error('Key Value connection unavailable');
  } finally {
    clearTimeout(timer);
  }
  return {
    async eval(script, keys, args, commandTimeoutMs) {
      assertUsableDeadline(commandTimeoutMs);
      try {
        if (!client.isReady) throw new Error('Key Value connection unavailable');
        return await client.withCommandOptions({ timeout: commandTimeoutMs }).eval(script, {
          keys,
          arguments: args,
        });
      } catch {
        throw new Error('Key Value command unavailable');
      }
    },
    close() {
      if (client.isOpen) client.destroy();
    },
  };
}

/** Allowlist: a deny-list of credential names is never complete. */
const FORWARDABLE_REQUEST_HEADERS = new Set([
  'accept',
  'accept-encoding',
  'accept-language',
  'user-agent',
  'if-none-match',
  'if-modified-since',
]);
export const IDENTITY_DENY_LIST = [
  'user_id',
  'userId',
  'user',
  'username',
  'useremail',
  'email',
  'identifier',
  'targetUserId',
  'targetEmail',
  'target_user_id',
  'target_email',
  'targetuser',
  'targetusername',
  'targetuseremail',
] as const;

const NORMALIZED_IDENTITY_FIELDS = new Set(IDENTITY_DENY_LIST.map(normalizeFieldName));
export interface UnauthenticatedGetOptions {
  readonly url: string | URL;
  /** Remaining request budget in ms. `undefined` means no timeout. Key is required so omission is visible. */
  readonly deadlineMs: number | undefined;
  /** Inbound request id, or `undefined` to mint one that does not join. Key required for the same reason. */
  readonly correlationId: string | undefined;
  /** Filtered through FORWARDABLE_REQUEST_HEADERS. Correlation id is set after, so it cannot be overridden. */
  readonly headers?: Headers;
  /**
   * Required: fetch defaults to `follow`. Key-set fetches must pass `manual`.
   * Literal union, not DOM `RequestRedirect` — adding DOM lib would make `self` a live egress binding.
   */
  readonly redirect: 'error' | 'follow' | 'manual';
}

/** Refuse budgets `AbortSignal.timeout` cannot honour (≤0 or non-finite). */
function assertUsableDeadline(deadlineMs: number | undefined): void {
  if (deadlineMs === undefined) return;

  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) {
    throw new TypeError('Upstream deadline must be a positive finite number of milliseconds');
  }
}

/**
 * Same check without the absent-deadline hatch. Auth-server calls must always be bounded;
 * an absent deadline attaches no abort signal. Kept separate from `assertUsableDeadline`:
 * the key-set GET may run unbounded; one shared optional helper would re-open the hatch.
 */
function requireUsableDeadline(deadlineMs: number): void {
  if (!Number.isFinite(deadlineMs) || deadlineMs <= 0) {
    throw new TypeError(
      'Authorization-server calls require a positive finite deadline in milliseconds. This ' +
        'request carries a slice of the one end-to-end budget and may not run unbounded.'
    );
  }
}

/**
 * GET with no credential. Headers are allowlisted, so Authorization/Cookie never reach the wire.
 * No query/body assembly, so the identity deny-list does not apply on this path.
 */
export async function getWithoutCredential(options: UnauthenticatedGetOptions): Promise<Response> {
  assertUsableDeadline(options.deadlineMs);

  const headers = new Headers();
  options.headers?.forEach((value, name) => {
    if (FORWARDABLE_REQUEST_HEADERS.has(name.toLowerCase())) {
      headers.set(name, value);
    }
  });
  headers.set(CORRELATION_ID_HEADER, options.correlationId ?? crypto.randomUUID());

  return fetch(String(options.url), {
    method: 'GET',
    headers,
    redirect: options.redirect,
    ...(options.deadlineMs === undefined
      ? {}
      : { signal: AbortSignal.timeout(options.deadlineMs) }),
  });
}
export interface FormPostOptions {
  readonly url: string | URL;
  /** Server-assembled named fields. Never a caller's argument bag. */
  readonly form: Readonly<Record<string, string>>;
  /**
   * Remaining request-budget slice, in ms. Required: there is no unbounded form of this call.
   * The key-set GET keeps an optional deadline; that is a different contract.
   */
  readonly deadlineMs: number;
  /** Inbound request id, or `undefined` to mint one. Key required so omission is visible. */
  readonly correlationId: string | undefined;
  readonly redirect: 'error' | 'follow' | 'manual';
}

/**
 * Form-encoded POST with no `Authorization` header. Auth-server endpoints take
 * `private_key_jwt` in the body. Identity deny-list applies and refuses loudly (a
 * server-assembled identity field is a call-site bug, not an untrusted arg to strip).
 */
export async function postFormWithoutCredential(options: FormPostOptions): Promise<Response> {
  requireUsableDeadline(options.deadlineMs);

  const body = new URLSearchParams();
  for (const [field, value] of Object.entries(options.form)) {
    if (isIdentityField(field)) {
      throw new TypeError(
        `Refusing to send the identity field "${field}" to the authorization server. Identity is ` +
          'derived from the subject token by the issuer, never taken from a request parameter.'
      );
    }
    body.set(field, value);
  }

  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' });
  headers.set(CORRELATION_ID_HEADER, options.correlationId ?? crypto.randomUUID());

  // Unconditional: the deadline is required, so there is no arm where a signal is absent.
  return fetch(String(options.url), {
    method: 'POST',
    headers,
    body: body.toString(),
    redirect: options.redirect,
    signal: AbortSignal.timeout(options.deadlineMs),
  });
}

function normalizeFieldName(field: string): string {
  return field.replaceAll(/[^a-zA-Z0-9]/g, '').toLowerCase();
}

export function isIdentityField(field: string): boolean {
  return NORMALIZED_IDENTITY_FIELDS.has(normalizeFieldName(field));
}
export interface IdentityFieldStrippedEvent {
  readonly event: 'client_identity_field_stripped';
  readonly field: string;
}

export type IdentityFieldLogger = (event: IdentityFieldStrippedEvent) => void;
const MAX_LOGGED_IDENTITY_FIELD_LENGTH = 128;
const MAX_IDENTITY_WARNINGS_PER_REQUEST = 20;
function logIdentityFieldStripped(event: IdentityFieldStrippedEvent): void {
  console.warn(
    JSON.stringify({
      level: 'warn',
      event: event.event,
      field: event.field,
    })
  );
}

function toSearchValue(field: string, value: unknown): string | undefined {
  if (value === null || value === undefined) return undefined;

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }

  throw new TypeError(`Declared tool parameter "${field}" must be a scalar value`);
}

export function selectDeclaredToolParameters(
  toolArguments: Readonly<Record<string, unknown>>,
  declaredParameters: readonly string[],
  onIdentityFieldStripped: IdentityFieldLogger = logIdentityFieldStripped
): Record<string, string> {
  const declared = new Set(declaredParameters);
  const selected: Record<string, string> = {};
  let identityWarnings = 0;
  for (const [field, value] of Object.entries(toolArguments)) {
    if (isIdentityField(field)) {
      if (identityWarnings < MAX_IDENTITY_WARNINGS_PER_REQUEST) {
        onIdentityFieldStripped({
          event: 'client_identity_field_stripped',
          field: field.slice(0, MAX_LOGGED_IDENTITY_FIELD_LENGTH),
        });
        identityWarnings += 1;
      }

      continue;
    }

    if (!declared.has(field)) continue;

    const searchValue = toSearchValue(field, value);
    if (searchValue !== undefined) {
      selected[field] = searchValue;
    }
  }

  return selected;
}
/** Raw and decoded path segments; malformed escapes keep the raw form only. */
function comparablePathSegments(pathname: string): string[] {
  const comparable: string[] = [];

  for (const segment of pathname.split('/')) {
    comparable.push(segment);

    try {
      comparable.push(decodeURIComponent(segment));
    } catch {
      // malformed escape — raw segment above is still compared
    }
  }

  return comparable;
}

function assertSafeUpstreamUrl(
  url: URL,
  baseUrl: URL,
  toolArguments: Readonly<Record<string, unknown>>
): void {
  if (url.origin !== baseUrl.origin) {
    throw new TypeError('Upstream path must remain on the configured origin');
  }

  if (url.search !== '' || url.hash !== '') {
    throw new TypeError('Upstream path must not include a query or fragment');
  }

  const pathSegments = comparablePathSegments(url.pathname);

  for (const [field, value] of Object.entries(toolArguments)) {
    if (!isIdentityField(field)) continue;

    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
      continue;
    }

    const identityValue = String(value);
    if (identityValue !== '' && pathSegments.includes(identityValue)) {
      throw new TypeError('Client-supplied identity must not appear in the upstream path');
    }
  }
}
export interface UpstreamRequest {
  readonly baseUrl: string;
  readonly path: string;
  readonly declaredParameters: readonly string[];
  readonly toolArguments?: Readonly<Record<string, unknown>>;
  readonly deadlineMs: number;
  readonly correlationId: string | undefined;
}

export async function fetchUpstream(request: UpstreamRequest): Promise<Response> {
  const baseUrl = new URL(request.baseUrl);
  const url = new URL(request.path, baseUrl);
  const toolArguments = request.toolArguments ?? {};

  assertSafeUpstreamUrl(url, baseUrl, toolArguments);

  const parameters = selectDeclaredToolParameters(toolArguments, request.declaredParameters);

  for (const [field, value] of Object.entries(parameters)) {
    url.searchParams.set(field, value);
  }

  return getWithoutCredential({
    url,
    deadlineMs: request.deadlineMs,
    correlationId: request.correlationId,
    redirect: 'error',
  });
}

/** Generic write boundary. Tools own schemas; this module owns outbound policy. */
export interface CredentialedJsonPost {
  readonly baseUrl: string;
  readonly path: string;
  readonly declaredFields: readonly string[];
  readonly body: Readonly<Record<string, unknown>>;
  readonly credential: string;
  readonly idempotencyKeyHash: string;
  readonly correlationId: string;
  readonly deadlineMs: number;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const reader = response.body?.getReader();
  if (!reader) throw new TypeError('Upstream response is empty');
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk: unknown = next.value;
      if (!(chunk instanceof Uint8Array)) throw new TypeError('Invalid response chunk');
      size += chunk.byteLength;
      if (size > 32 * 1024) throw new TypeError('Upstream response exceeds its limit');
      chunks.push(chunk);
    }
  } finally {
    await reader.cancel();
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

export async function postCredentialedJson(
  request: CredentialedJsonPost
): Promise<{ status: number; body?: unknown }> {
  const base = new URL(request.baseUrl);
  const url = new URL(request.path, base);
  if (
    base.protocol !== 'https:' ||
    base.username ||
    base.password ||
    base.search ||
    base.hash ||
    url.username ||
    url.password
  )
    throw new TypeError('Writes require the configured HTTPS backend');
  assertSafeUpstreamUrl(url, base, request.body);
  if (
    !/^[0-9a-f]{64}$/.test(request.idempotencyKeyHash) ||
    !/^[A-Za-z0-9\-._~+/]+=*$/.test(request.credential)
  ) {
    throw new TypeError('A backend credential and confirmation digest are required');
  }
  if (!Number.isSafeInteger(request.deadlineMs) || request.deadlineMs <= 0) {
    throw new TypeError('A positive remaining deadline is required');
  }
  const declared = new Set(request.declaredFields);
  for (const field of Object.keys(request.body)) {
    if (isIdentityField(field) || !declared.has(field)) {
      throw new TypeError('Undeclared or identity-bearing JSON field');
    }
  }
  const body = JSON.stringify(request.body);
  if (Buffer.byteLength(body, 'utf8') > 32 * 1024) throw new TypeError('Request is too large');
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      authorization: `Bearer ${request.credential}`,
      'idempotency-key': request.idempotencyKeyHash,
      [CORRELATION_ID_HEADER]: request.correlationId,
    },
    body,
    redirect: 'error',
    signal: AbortSignal.timeout(request.deadlineMs),
  });
  if (!response.ok) {
    await response.body?.cancel();
    return { status: response.status };
  }
  return { status: response.status, body: await readBoundedJson(response) };
}
