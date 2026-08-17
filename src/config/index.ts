/**
 * Environment loading and startup validation.
 * Partial: only the variables needed to boot the transport and verify an inbound token.
 * Nothing security-relevant defaults; absent means refuse to start.
 */

export interface ServerConfig {
  readonly port: number;
  /** Hostnames only — the Origin guard is port-agnostic. */
  readonly allowedOriginHostnames: readonly string[];
  readonly jwksUrl: URL;
  readonly expectedIssuer: string;
  /**
   * Canonical resource identifier including its path. Also the expected audience — there is no
   * second variable for it. Metadata location is derived from it too.
   */
  readonly resourceIdentifier: string;
  /**
   * Key-set reuse lifetime in ms (configured in seconds). Too long is a revocation gap; too
   * short is a DoS vector against the issuer.
   */
  readonly jwksCacheMaxAgeMs: number;
  /**
   * End-to-end deadline for one MCP request, not a per-call timeout. Later stages
   * (introspection, audit, exchange, upstream) share this budget — no stage gets a fresh copy.
   */
  readonly requestDeadlineMs: number;
}

function originToHostname(origin: string): string {
  try {
    const hostname = new URL(origin).hostname;
    if (hostname === '') {
      throw new Error('empty hostname');
    }
    return hostname;
  } catch {
    throw new Error(`MCP_ALLOWED_ORIGINS entry is not a valid URL: ${origin}`);
  }
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  // Trailing newlines in deployment vars are invisible; issuer/audience compare byte for byte.
  return value.trim();
}

/** Errors name the variable, never the value — the next caller may be a key. */
function parseUrl(name: string, value: string): URL {
  try {
    return new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
}

/**
 * HTTPS only. A cleartext JWKS can be substituted and every pin then holds against attacker keys.
 * A cleartext resource identifier publishes a cleartext challenge pointer.
 * Returns both forms: some callers need the raw string, some the URL.
 */
function requiredHttps(name: string): { readonly value: string; readonly url: URL } {
  const value = required(name);
  const url = parseUrl(name, value);
  if (url.protocol !== 'https:') {
    throw new Error(`${name} must use https: over cleartext it can be substituted in transit`);
  }
  return { value, url };
}

/**
 * Scheme-pinned, not normalised. The issuer is compared byte-for-byte against a claim someone
 * else mints; `href` would append a trailing slash and reject every token.
 */
function requiredHttpsVerbatim(name: string): string {
  return requiredHttps(name).value;
}

function requiredHttpsUrl(name: string): URL {
  return requiredHttps(name).url;
}

/**
 * Scheme-pinned and normalised — opposite of the issuer. This server publishes the canonical
 * form in its metadata, so the authorization server must echo it as `aud`.
 */
function requiredResourceIdentifier(name: string): string {
  const { value, url } = requiredHttps(name);
  if (url.pathname === '/' || url.pathname === '') {
    throw new Error(`${name} must include the resource path, for example https://mcp.example/mcp`);
  }
  // Test the raw value: a trailing `?` or `#` parses to empty search/hash while `href` keeps it.
  if (value.includes('?') || value.includes('#')) {
    throw new Error(`${name} must carry no query string and no fragment`);
  }
  // `origin` drops userinfo, `href` keeps it — audience would carry credentials the pointer does not.
  if (url.username !== '' || url.password !== '') {
    throw new Error(`${name} must carry no userinfo`);
  }
  return url.href;
}

/**
 * Digits only, tested before parsing. `parseInt` stops at the first non-digit, so `3000abc`
 * would become 3000 — a port nobody configured.
 */
function requiredWholeNumber(name: string, min: number, max: number): number {
  const raw = required(name);
  const value = /^\d+$/.test(raw) ? Number.parseInt(raw, 10) : Number.NaN;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be a base-10 integer between ${String(min)} and ${String(max)}`);
  }
  return value;
}

/** One day. Beyond this is a revocation gap nobody intended. */
const MAX_JWKS_CACHE_TTL_S = 86_400;

/**
 * Floor is 60s, not 1: jose refetches when the cache ages out, and its unknown-kid cooldown
 * does not limit that refetch. A shorter TTL turns every inbound request into an outbound one.
 */
const MIN_JWKS_CACHE_TTL_S = 60;

/** Ten minutes. Longer is a hung request, not a slow backend. */
const MAX_REQUEST_DEADLINE_MS = 600_000;

export function loadConfig(): ServerConfig {
  const port = requiredWholeNumber('PORT', 1, 65535);

  const allowedOrigins = required('MCP_ALLOWED_ORIGINS')
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  if (allowedOrigins.length === 0) {
    throw new Error('MCP_ALLOWED_ORIGINS must list at least one origin');
  }

  const allowedOriginHostnames = [
    ...new Set(allowedOrigins.map((origin) => originToHostname(origin))),
  ];

  return {
    port,
    allowedOriginHostnames,
    jwksUrl: requiredHttpsUrl('MCP_JWKS_URL'),
    expectedIssuer: requiredHttpsVerbatim('MCP_EXPECTED_ISSUER'),
    resourceIdentifier: requiredResourceIdentifier('MCP_RESOURCE_IDENTIFIER'),
    jwksCacheMaxAgeMs:
      requiredWholeNumber('MCP_JWKS_CACHE_TTL_S', MIN_JWKS_CACHE_TTL_S, MAX_JWKS_CACHE_TTL_S) *
      1000,
    requestDeadlineMs: requiredWholeNumber('MCP_REQUEST_DEADLINE_MS', 1, MAX_REQUEST_DEADLINE_MS),
  };
}
