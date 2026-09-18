/**
 * Environment loading and startup validation.
 * Partial: only the variables needed to boot the transport, verify an inbound token, and
 * introspect the grant behind it.
 * Nothing security-relevant defaults; absent means refuse to start.
 */

import { createPrivateKey, type KeyObject } from 'node:crypto';

export interface ServerConfig {
  readonly port: number;
  /** Hostnames only — the Origin guard is port-agnostic. */
  readonly allowedOriginHostnames: readonly string[];
  readonly nutrihelpApiBaseUrl: string;
  readonly jwksUrl: URL;
  readonly expectedIssuer: string;
  /** Authorization server issuer, published verbatim in metadata. */
  readonly authServerUrl: string;
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
  /**
   * This server's client id at the authorization server (`iss`/`sub` of assertions, `act` of
   * the exchanged credential). Verbatim, never normalised. Distinct from `resourceIdentifier`.
   */
  readonly clientId: string;
  /**
   * Own credential for `private_key_jwt`. Parsed at startup so a bad key fails boot, not the
   * first introspection as an outage.
   */
  readonly clientAssertionKey: KeyObject;
  /**
   * How long an `active: false` may be reused, in ms. Never caches a positive answer; never
   * permits dispatch. Default 0 means ask every time.
   */
  readonly revokedGrantCacheMaxAgeMs: number;
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

function requiredApiBaseUrl(): string {
  const value = required('NUTRIHELP_API_BASE_URL');
  const url = parseUrl('NUTRIHELP_API_BASE_URL', value);
  if (url.protocol !== 'https:') {
    throw new Error(
      'NUTRIHELP_API_BASE_URL must use https: over cleartext it can be substituted in transit'
    );
  }
  return value;
}

/** Shape refusals for values published in metadata. Shared so normalisation stays a separate choice. */
function refuseUnpublishableShape(name: string, value: string, url: URL): void {
  // Test the raw value: a trailing `?` or `#` parses to empty search/hash while `href` keeps it.
  if (value.includes('?') || value.includes('#')) {
    throw new Error(`${name} must carry no query string and no fragment`);
  }
  // `origin` drops userinfo, `href` keeps it. Published verbatim, this puts a credential in a
  // document served to unauthenticated callers.
  if (url.username !== '' || url.password !== '') {
    throw new Error(`${name} must carry no userinfo`);
  }
}

/** Refused in resource paths — Express re-reads these as route-pattern syntax. */
const ROUTE_PATTERN_METACHARACTERS = /[:*(){}?+[\]]/;

/**
 * Scheme-pinned and normalised — opposite of the issuer. This server publishes the canonical
 * form in its metadata, so the authorization server must echo it as `aud`.
 */
function requiredResourceIdentifier(name: string): string {
  const { value, url } = requiredHttps(name);
  if (url.pathname === '/' || url.pathname === '') {
    throw new Error(`${name} must include the resource path, for example https://mcp.example/mcp`);
  }
  refuseUnpublishableShape(name, value, url);
  if (ROUTE_PATTERN_METACHARACTERS.test(url.pathname)) {
    throw new Error(
      `${name} path must carry no route-pattern metacharacter, because the metadata route is derived from it`
    );
  }
  return url.href;
}

/**
 * Scheme-pinned, path-bearing and **verbatim**: the AS compares this string as registered, so
 * normalising would break `iss`/`sub`. The path keeps it from collapsing into the resource id.
 */
function requiredClientIdentifier(name: string): string {
  const { value, url } = requiredHttps(name);
  if (url.pathname === '/' || url.pathname === '') {
    throw new Error(
      `${name} must carry a path distinguishing it from the resource identifier, for example https://mcp.example/client`
    );
  }
  refuseUnpublishableShape(name, value, url);
  return value;
}

/** Scheme-pinned and verbatim, with publishability shape checks. */
function requiredIssuerIdentifier(name: string): string {
  const { value, url } = requiredHttps(name);
  refuseUnpublishableShape(name, value, url);
  return value;
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

/**
 * Five minutes. A revoked grant that keeps being refused for longer than this is no longer
 * blunting abuse, it is a stale denial nobody can clear without a restart.
 */
const MAX_REVOKED_GRANT_CACHE_TTL_S = 300;

/**
 * A bounded whole number that may be absent, unlike `requiredWholeNumber`. Only for values where
 * absence is a real choice rather than a missing decision — an empty string is treated as absent
 * so a blank service-environment entry does not fail startup on a knob that has a safe default.
 */
function optionalWholeNumber(name: string, min: number, max: number, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const value = /^\d+$/.test(raw.trim()) ? Number.parseInt(raw.trim(), 10) : Number.NaN;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(
      `${name} must be a base-10 integer between ${String(min)} and ${String(max)}, or be unset`
    );
  }
  return value;
}

/**
 * Parse PEM at startup. Asymmetric only: `private_key_jwt` is verified against a published
 * public key. A symmetric secret is the wrong credential shape for this variable.
 */
function requiredPrivateKey(name: string): KeyObject {
  const raw = required(name);
  let key: KeyObject;
  try {
    key = createPrivateKey(raw);
  } catch {
    throw new Error(
      `${name} is not a readable private key. Supply a PKCS#8 PEM. The value is this server's ` +
        'own credential, not a platform secret, and it is never logged.'
    );
  }
  if (key.asymmetricKeyType === undefined) {
    throw new Error(`${name} must be an asymmetric private key, so the issuer can verify it.`);
  }
  return key;
}

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

  const resourceIdentifier = requiredResourceIdentifier('MCP_RESOURCE_IDENTIFIER');
  const clientId = requiredClientIdentifier('MCP_CLIENT_ID');

  // Resource is stored normalised, client verbatim — so case-only twins name one registration
  // as different strings. Compare via URL.href (the discriminating check); raw equality is
  // defence in depth if resource ever stops being normalised.
  if (
    clientId === resourceIdentifier ||
    new URL(clientId).href === new URL(resourceIdentifier).href
  ) {
    throw new Error(
      'MCP_CLIENT_ID must differ from MCP_RESOURCE_IDENTIFIER: resource and client are separate registrations at the authorization server'
    );
  }

  return {
    port,
    allowedOriginHostnames,
    nutrihelpApiBaseUrl: requiredApiBaseUrl(),
    jwksUrl: requiredHttpsUrl('MCP_JWKS_URL'),
    expectedIssuer: requiredHttpsVerbatim('MCP_EXPECTED_ISSUER'),
    authServerUrl: requiredIssuerIdentifier('MCP_AUTH_SERVER_URL'),
    resourceIdentifier,
    clientId,
    jwksCacheMaxAgeMs:
      requiredWholeNumber('MCP_JWKS_CACHE_TTL_S', MIN_JWKS_CACHE_TTL_S, MAX_JWKS_CACHE_TTL_S) *
      1000,
    requestDeadlineMs: requiredWholeNumber('MCP_REQUEST_DEADLINE_MS', 1, MAX_REQUEST_DEADLINE_MS),
    clientAssertionKey: requiredPrivateKey('MCP_CLIENT_ASSERTION_KEY'),
    revokedGrantCacheMaxAgeMs:
      optionalWholeNumber('MCP_REVOKED_GRANT_CACHE_TTL_S', 0, MAX_REVOKED_GRANT_CACHE_TTL_S, 0) *
      1000,
  };
}
