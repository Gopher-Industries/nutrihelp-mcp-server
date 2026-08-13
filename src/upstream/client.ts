/**
 * The single point through which every outbound call to the NutriHelp backend passes.
 * Strips deny-listed identity fields from outbound query parameters before dispatch.
 *
 * Minimal scaffolding (ticket 28) — covers query-parameter stripping for GET requests,
 * since that's all any tool currently needs. Body/header stripping and the token-exchange
 * assertion (ticket 39) are not yet implemented.
 */

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
  const url = new URL(request.path, request.baseUrl);
  const safeParams = stripDeniedParams(request.searchParams ?? {});
  for (const [key, value] of Object.entries(safeParams)) {
    url.searchParams.set(key, value);
  }
  return fetch(url);
}