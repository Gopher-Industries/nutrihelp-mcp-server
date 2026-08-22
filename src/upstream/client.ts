/**
 * The only module permitted to make an outbound HTTP call.
 *
 * Supports unauthenticated GET and declared query assembly with identity filtering.
 * Credential attachment and retry with backoff/jitter remain future work.
 * Do not improvise outbound policy in a caller.
 */

/**
 * Conventional name until the backend contract pins it. If the caller passes `undefined`, a
 * fresh id is minted — that one does not join the inbound request.
 */
export const CORRELATION_ID_HEADER = 'x-correlation-id';

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

/**
 * GET with no credential. Headers are allowlisted, so Authorization/Cookie never reach the wire.
 * No query/body assembly, so the identity deny-list does not apply on this path.
 */
export async function getWithoutCredential(options: UnauthenticatedGetOptions): Promise<Response> {
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

  const pathSegments = url.pathname.split('/').map((segment) => decodeURIComponent(segment));

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
  readonly deadlineMs: number | undefined;
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
