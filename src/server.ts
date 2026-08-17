/** Composition root. Wiring only, no logic. */

import 'dotenv/config';

import { McpServer } from '@modelcontextprotocol/server';
import { loadConfig } from './config/index.ts';
import { protectedResourceMetadataUrl } from './auth/challenge.ts';
import { createTokenValidator } from './auth/tokenValidator.ts';
import { createHttpApp } from './transport/http.ts';

const config = loadConfig();

const tokenValidator = createTokenValidator({
  jwksUrl: config.jwksUrl,
  expectedIssuer: config.expectedIssuer,
  expectedAudience: config.resourceIdentifier,
  cacheMaxAgeMs: config.jwksCacheMaxAgeMs,
  requestDeadlineMs: config.requestDeadlineMs,
  // Unset on purpose: fallback is the one egress door, and this file must not import it.
});

const app = createHttpApp({
  factory: () =>
    new McpServer({
      name: 'nutrihelp-mcp-server',
      version: '1.0.0',
    }),
  allowedOriginHostnames: config.allowedOriginHostnames,
  authorization: {
    validator: tokenValidator,
    resourceMetadataUrl: protectedResourceMetadataUrl(config.resourceIdentifier),
    // Unset until the tool-to-scope map exists.
  },
  onError: (error: Error) => {
    // TODO(logging): pino. Message only — jose errors can carry a decoded token payload.
    console.error(JSON.stringify({ level: 'error', msg: error.message }));
  },
});

app.listen(config.port, () => {
  console.log(JSON.stringify({ level: 'info', msg: 'listening', port: config.port }));
});
