/**
 * The deployment configuration every security test runs against, in test clothing.
 *
 * Hostnames are `.test` on purpose: `disableNetConnect()` turns any unmocked call into a loud
 * failure, and a `.test` TLD cannot resolve even if that guard were removed.
 *
 * No `SUPABASE_URL`, no `SUPABASE_ANON_KEY`, no `JWT_TOKEN` — absent by construction, in
 * fixtures as well as in configuration.
 */

export const AUTH_SERVER_ORIGIN = 'https://auth.nutrihelp.test';
export const MCP_EXPECTED_ISSUER = AUTH_SERVER_ORIGIN;
export const MCP_RESOURCE_IDENTIFIER = 'https://mcp.nutrihelp.test/mcp';

/** What a `WWW-Authenticate` challenge must carry in `resource_metadata`. Path-inserted per
 *  RFC 9728, and byte-identical to MCP_RESOURCE_IDENTIFIER or a conformant client discards it. */
export const RESOURCE_METADATA_URL =
  'https://mcp.nutrihelp.test/.well-known/oauth-protected-resource/mcp';

export const MCP_JWKS_URL = `${AUTH_SERVER_ORIGIN}/.well-known/jwks.json`;
export const INTROSPECTION_PATH = '/api/oauth/introspect';
export const TOKEN_EXCHANGE_PATH = '/api/oauth/token';

export const NUTRIHELP_API_ORIGIN = 'https://api.nutrihelp.test';
export const FOODDATA_SEARCH_PATH = '/api/fooddata/search';
export const MEALPLAN_ME_PATH = '/api/mealplan/me';

/** The deployed route whose controller falls back to a request-supplied identifier. Not a
 *  backing endpoint; registered so that reaching it at all is observable. */
export const MEALPLAN_LEGACY_PATH = '/api/mealplan';

/** Audit ingest shares an origin with the resource endpoints and is a POST, so anything
 *  counting "writes" by method and origin counts audit envelopes too — and a `started` envelope
 *  precedes every upstream call. Excluding it is what stops ticket 34 breaking the write counts. */
export const AUDIT_INGEST_PATH = '/api/security-events';

/**
 * Any backend API path that is not audit ingest. Keep the lookahead in step with the constant
 * above.
 *
 * PLAN GAP: the meal-log write's auth, ownership, idempotency, payload and table are all
 * specified, but no route path is. Writes are therefore counted by HTTP method against the
 * API origin rather than by a path string nobody has fixed.
 */
export const ANY_API_PATH = /^\/api\/(?!security-events)/;

export const ALLOWED_ORIGIN = 'https://claude.ai';
export const ALLOWED_ORIGIN_HOSTNAMES = ['claude.ai'] as const;

export const SCOPES = {
  nutritionRead: 'nutrition:read',
  mealplanRead: 'mealplan:read',
  meallogWrite: 'meallog:write',
} as const;

export const ALL_SCOPES = [SCOPES.nutritionRead, SCOPES.mealplanRead, SCOPES.meallogWrite];

export const USER_A = 'user-a-0001';
export const USER_B = 'user-b-0002';

export const CLIENT_ID = 'https://client.test/mcp-client.json';
export const GRANT_A = 'grant-a-1111';

/**
 * TODO(ticket-28): replace with
 * `import { IDENTITY_DENY_LIST } from '../../src/upstream/client.ts'`.
 *
 * Declared here because that module does not exist yet and the module list is fixed.
 * Until the swap this is a COPY, so a production list *shorter* than this one still passes
 * every test here — the drift is invisible in exactly the direction that matters.
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
