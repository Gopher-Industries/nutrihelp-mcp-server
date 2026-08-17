/**
 * Bearer `WWW-Authenticate` builders. Pure string construction — whether to challenge is
 * decided on the request path.
 */

/** Quote, backslash, or a non-printable would forge a second parameter or header. Drop, don't escape. */
const NOT_SAFE_IN_A_QUOTED_STRING = /[^\x20-\x7e]|["\\]/g;

/** Same sanitiser as headers: a newline in a log value forges an entry. */
export function safeInOneLine(value: string): string {
  return value.replace(NOT_SAFE_IN_A_QUOTED_STRING, '');
}

function quoted(value: string): string {
  return `"${safeInOneLine(value)}"`;
}

/**
 * Well-known segment inserted between origin and resource path:
 * `https://host/mcp` → `https://host/.well-known/oauth-protected-resource/mcp`.
 * Challenge pointer and document `resource` must be byte-identical, so both come from one config value.
 */
export function protectedResourceMetadataUrl(resourceIdentifier: string): string {
  const resource = new URL(resourceIdentifier);
  return `${resource.origin}/.well-known/oauth-protected-resource${resource.pathname}`;
}

/** No credential presented. No `error` parameter — this starts the connect flow. */
export function unauthenticatedChallenge(metadataUrl: string): string {
  return `Bearer resource_metadata=${quoted(metadataUrl)}`;
}

/**
 * Credential presented and did not verify. Never says which check failed: that helps an
 * attacker probing the verifier; a legitimate client refreshes either way.
 */
export function invalidTokenChallenge(metadataUrl: string): string {
  return `Bearer error="invalid_token", resource_metadata=${quoted(metadataUrl)}`;
}

/**
 * Verified token, missing scope. 403, never 401 — 401 would refresh the same scopes and fail again.
 * Naming the required scope is what lets a client request step-up.
 */
export function insufficientScopeChallenge(metadataUrl: string, requiredScope: string): string {
  return [
    'Bearer error="insufficient_scope"',
    `scope=${quoted(requiredScope)}`,
    `resource_metadata=${quoted(metadataUrl)}`,
  ].join(', ');
}
