/** Composition root. Wiring only, no logic. */

import 'dotenv/config';

import { McpServer } from '@modelcontextprotocol/server';
import { loadConfig } from './config/index.ts';
import { protectedResourceMetadata } from './auth/metadata.ts';
import { protectedResourceMetadataUrl } from './auth/challenge.ts';
import { createTokenValidator } from './auth/tokenValidator.ts';
import { createRevocationChecker } from './auth/revocation.ts';
import { createHttpApp } from './transport/http.ts';
import { registerTools } from './tools/registry.ts';

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
 * Joined here rather than configured: the host is a configured value and the path is fixed by
 * the introspection contract, so a seventeenth variable would let the two drift apart for a
 * value neither side may choose independently.
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

const app = createHttpApp({
  factory: (ctx) => {
    const server = new McpServer({
      name: 'nutrihelp-mcp-server',
      version: '1.0.0',
    });

    registerTools(server, ctx, config);

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
    requestDeadlineMs: config.requestDeadlineMs,
  },
  onError: (error: Error) => {
    // TODO(logging): pino. Message only — jose errors can carry a decoded token payload.
    console.error(JSON.stringify({ level: 'error', msg: error.message }));
  },
});
app.listen(config.port, () => {
  console.log(JSON.stringify({ level: 'info', msg: 'listening', port: config.port }));
});
