/**
 * The deployment configuration every security test runs against, in test clothing.
 *
 * Hostnames are `.test` on purpose: `disableNetConnect()` turns any unmocked call into a loud
 * failure, and a `.test` TLD cannot resolve even if that guard were removed.
 *
 * No `SUPABASE_URL`, no `SUPABASE_ANON_KEY`, no `JWT_TOKEN` — absent by construction, in
 * fixtures as well as in configuration.
 */

import { SCOPE_NAMES } from '../../src/auth/scopes.ts';

export const AUTH_SERVER_ORIGIN = 'https://auth.nutrihelp.test';
export const MCP_EXPECTED_ISSUER = AUTH_SERVER_ORIGIN;
export const MCP_RESOURCE_IDENTIFIER = 'https://mcp.nutrihelp.test/mcp';

/** What a `WWW-Authenticate` challenge must carry in `resource_metadata`. Path-inserted per
 *  RFC 9728, and byte-identical to MCP_RESOURCE_IDENTIFIER or a conformant client discards it. */
export const RESOURCE_METADATA_URL =
  'https://mcp.nutrihelp.test/.well-known/oauth-protected-resource/mcp';

/** Published in this server's metadata as where the connect flow starts. */
export const MCP_AUTH_SERVER_URL = AUTH_SERVER_ORIGIN;

export const MCP_JWKS_URL = `${AUTH_SERVER_ORIGIN}/.well-known/jwks.json`;
export const INTROSPECTION_PATH = '/api/oauth/introspect';
export const TOKEN_EXCHANGE_PATH = '/api/oauth/token';

export const NUTRIHELP_API_ORIGIN = 'https://api.nutrihelp.test';
export const NUTRIHELP_API_BASE_URL = NUTRIHELP_API_ORIGIN;
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

/**
 * Production source of truth for the scope set, re-exported rather than restated. A fixture copy
 * is a second hand-maintained statement of one set, and the drift is invisible because each reads
 * complete on its own — the suites would keep passing against scope names the server no longer
 * knows. The contents are pinned in `test/unit/auth/scopes.test.ts`, not here.
 */
export { SCOPES } from '../../src/auth/scopes.ts';

/**
 * Derived, and **frozen**: this one array object is the default `scopes` of every forged grant and
 * of the always-active fixture, so a suite that sorted or spliced it would mutate every other
 * suite's grant. Spread it at a call site that needs a mutable copy.
 */
export const ALL_SCOPES: readonly string[] = Object.freeze([...SCOPE_NAMES]);

export const USER_A = 'user-a-0001';
export const USER_B = 'user-b-0002';

export const CLIENT_ID = 'https://client.test/mcp-client.json';
export const GRANT_A = 'grant-a-1111';

/**
 * This server's client id (`MCP_CLIENT_ID` / assertion `iss`+`sub`). Not `CLIENT_ID` (assistant
 * in an inbound token) and not `MCP_RESOURCE_IDENTIFIER` — config refuses if those two match.
 * Path `/client` differs from the resource's `/mcp` by more than spelling.
 */
export const MCP_CLIENT_ID = 'https://mcp.nutrihelp.test/client';

/** Production source of truth for blocked identity fields. */
export { IDENTITY_DENY_LIST } from '../../src/upstream/client.ts';
