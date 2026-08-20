/** The single point through which every outbound call to the NutriHelp backend passes. */

export const IDENTITY_DENY_LIST = [
  'user_id',
  'userId',
  'email',
  'targetUserId',
  'targetEmail',
  'target_user_id',
  'target_email',
] as const;

export interface UpstreamRequest {
  readonly baseUrl: string;
  readonly path: string;
  readonly searchParams?: Record<string, string>;
  readonly deadlineMs?: number;
}

function stripDeniedParams(params: Record<string, string>): Record<string, string> {
  const clean: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    if (!(IDENTITY_DENY_LIST as readonly string[]).includes(key)) {
      clean[key] = value;
    }
  }
  return clean;
}

export async function fetchUpstream(request: UpstreamRequest): Promise<Response> {
  const baseUrl = new URL(request.baseUrl);
  const url = new URL(request.path, request.baseUrl);
  if (url.origin !== baseUrl.origin) {
    throw new Error('upstream path must stay on the configured origin');
  }
  const safeParams = stripDeniedParams(request.searchParams ?? {});
  for (const [key, value] of Object.entries(safeParams)) {
    url.searchParams.set(key, value);
  }
  return fetch(url, {
    ...(request.deadlineMs === undefined
      ? {}
      : { signal: AbortSignal.timeout(request.deadlineMs) }),
  });
}

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
