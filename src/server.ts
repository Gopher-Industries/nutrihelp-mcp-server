/** Composition root. Wiring only, no logic. */

import 'dotenv/config';

import { McpServer } from '@modelcontextprotocol/server';
import { loadConfig } from './config/index.ts';
import { protectedResourceMetadata } from './auth/metadata.ts';
import { protectedResourceMetadataUrl } from './auth/challenge.ts';
import { createTokenValidator } from './auth/tokenValidator.ts';
import { createRevocationChecker } from './auth/revocation.ts';
import { missingScopeFor } from './auth/scopes.ts';
import { createUpstreamCredentialProvider } from './auth/upstreamToken.ts';
import { createHttpApp } from './transport/http.ts';
import { AUDIT_ENQUEUE_NOT_IMPLEMENTED, registerTools } from './tools/registry.ts';

const config = loadConfig();

const tokenValidator = createTokenValidator({
  jwksUrl: config.jwksUrl,
  expectedIssuer: config.expectedIssuer,
  expectedAudience: config.resourceIdentifier,
  cacheMaxAgeMs: config.jwksCacheMaxAgeMs,
  requestDeadlineMs: config.requestDeadlineMs,
  // Unset on purpose: fallback is the one egress door, and this file must not import it.
});

/**
 * Joined rather than configured: the host is configured and the path is fixed by the contract, so
 * a seventeenth variable would let the two drift for a value neither side may choose alone.
 */
const introspectionUrl = new URL('/api/oauth/introspect', config.authServerUrl).href;

const revocationChecker = createRevocationChecker({
  introspectionUrl,
  clientId: config.clientId,
  clientAssertionKey: config.clientAssertionKey,
  resourceMetadataUrl: protectedResourceMetadataUrl(config.resourceIdentifier),
  negativeCacheMaxAgeMs: config.revokedGrantCacheMaxAgeMs,
  now: () => Date.now(),
  // Operational vs security: shared sink today, separated by `channel`.
  logOperational: (event) => {
    console.error(JSON.stringify({ level: 'warn', channel: 'operational', ...event }));
  },
  logSecurity: (event) => {
    console.error(JSON.stringify({ level: 'warn', channel: 'security', ...event }));
  },
});

/**
 * Same join, and it must **NOT** equal the introspection URL: the authorization server accepts an
 * assertion only at the endpoint the assertion names, so one shared value fails client
 * authentication at whichever endpoint it was not minted for.
 *
 * Recorded, not fixed: a second endpoint derived from `MCP_AUTH_SERVER_URL` doubles what that
 * variable's silent path-drop costs — a leading-slash join discards any path the base carries, so
 * an authorization server under a path prefix is now called at the origin root twice, not once.
 */
const tokenEndpointUrl = new URL('/api/oauth/token', config.authServerUrl).href;

/**
 * Step 4's minter. **Passed into `createHttpApp` as a required field**, the way the revocation
 * checker is — the transport cannot import this file without inverting the import chain, and an
 * omitted field would disable a step of the mandatory order with nothing to notice it.
 *
 * It is not consumed here and not consumed by the transport: the registry takes it per tool, and
 * only for a tool whose backing endpoint is credentialed.
 */
const upstreamCredentialProvider = createUpstreamCredentialProvider({
  tokenEndpointUrl,
  clientId: config.clientId,
  clientAssertionKey: config.clientAssertionKey,
  now: () => Date.now(),
  logOperational: (event) => {
    console.error(JSON.stringify({ level: 'warn', channel: 'operational', ...event }));
  },
  logSecurity: (event) => {
    console.error(JSON.stringify({ level: 'warn', channel: 'security', ...event }));
  },
});

/** Derived once: the challenge pointer, the served document and the registry's refusals agree. */
const resourceMetadataUrl = protectedResourceMetadataUrl(config.resourceIdentifier);

const app = createHttpApp({
  factory: (ctx, authorizationFor) => {
    const server = new McpServer({
      name: 'nutrihelp-mcp-server',
      version: '1.0.0',
    });

    registerTools(server, ctx, {
      nutrihelpApiBaseUrl: config.nutrihelpApiBaseUrl,
      // How dispatch reads what this request established. Handed in rather than imported: the
      // WeakMap is scoped to this app instance, so one instance cannot answer another's request.
      authorizationFor,
      resourceMetadataUrl,
      // Step 5 of the mandatory order, NAMED AND EMPTY. `src/audit/logger.ts` does not exist,
      // so every dispatch reaching a tool today has no durable audit record behind it. Stated
      // here rather than omitted: a composition that skips the field would read as satisfied.
      auditEnqueue: AUDIT_ENQUEUE_NOT_IMPLEMENTED,
    });

    return server;
  },
  allowedOriginHostnames: config.allowedOriginHostnames,
  resourceMetadata: protectedResourceMetadata({
    resourceIdentifier: config.resourceIdentifier,
    authorizationServers: [config.authServerUrl],
  }),
  authorization: {
    validator: tokenValidator,
    revocation: revocationChecker,
    credentials: upstreamCredentialProvider,
    requestDeadlineMs: config.requestDeadlineMs,
    // Step 3, straight from the frozen map. The transport carries the grant introspection just
    // established into this call as the third argument, so no hand-off record is involved.
    missingScopeFor,
  },
  onError: (error: Error) => {
    // TODO(logging): pino. Message only — jose errors can carry a decoded token payload.
    console.error(JSON.stringify({ level: 'error', msg: error.message }));
  },
});
app.listen(config.port, () => {
  console.log(JSON.stringify({ level: 'info', msg: 'listening', port: config.port }));
});
