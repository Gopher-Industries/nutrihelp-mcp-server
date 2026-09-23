/** Composition root. Wiring only, no logic. */

import 'dotenv/config';
import { pathToFileURL } from 'node:url';

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

import { connectKeyValue, type KeyValueConnection } from './upstream/client.ts';
import { ConfirmationError } from './errors.ts';
import { createConfirmationStore, type ConfirmationStoreOptions } from './consent/confirmation.ts';

/**
 * Opens the confirmation store for write tools. url is trusted
 * Render Key Value configuration, not model input.
 */
export async function connectConfirmationStore(
  url: string,
  options: ConfirmationStoreOptions = {}
) {
  let connection: KeyValueConnection;
  try {
    connection = await connectKeyValue(url, options.commandTimeoutMs ?? 1_000);
  } catch {
    throw new ConfirmationError('confirmation_store_unavailable');
  }
  try {
    return { ...createConfirmationStore(connection, options), close: connection.close };
  } catch (error) {
    connection.close();
    throw error;
  }
}

/** Keep importing the connection factory free of configuration reads and HTTP listeners. */
export async function startServer() {
  const config = loadConfig();

  const tokenValidator = createTokenValidator({
    jwksUrl: config.jwksUrl,
    expectedIssuer: config.expectedIssuer,
    expectedAudience: config.resourceIdentifier,
    cacheMaxAgeMs: config.jwksCacheMaxAgeMs,
    requestDeadlineMs: config.requestDeadlineMs,
    // Unset on purpose: key-set fetches use the default egress adapter.
  });

  /**
   * Joined rather than configured: the host is configured and the path is fixed by the contract, so
   * a separate variable would let the two drift for a value neither side may choose alone.
   */
  const introspectionUrl = new URL('/api/oauth/introspect', config.authServerUrl).href;

  /** Derived once: the challenge pointer, the served document and the registry's refusals agree. */
  const resourceMetadataUrl = protectedResourceMetadataUrl(config.resourceIdentifier);

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

  const leaseMs = config.requestDeadlineMs + 1_000;
  const confirmations = await connectConfirmationStore(config.redisUrl, {
    leaseMs,
    lifetimeMs: Math.max(300_000, leaseMs),
  });
  try {
    const app = createHttpApp({
      factory: (ctx, authorizationFor) => {
        const server = new McpServer({
          name: 'nutrihelp-mcp-server',
          version: '1.0.0',
        });

        registerTools(server, ctx, {
          confirmations,
          logConfirmationAnomaly: (event) => {
            console.error(JSON.stringify({ level: 'warn', channel: 'security', ...event }));
          },
          nutrihelpApiBaseUrl: config.nutrihelpApiBaseUrl,
          // How dispatch reads what this request established. Handed in rather than imported: the
          // WeakMap is scoped to this app instance, so one instance cannot answer another's request.
          authorizationFor,
          // The security channel, same shape and same sink as the revocation checker's above. A
          // dispatch denied at the trust boundary is security-relevant, and without this the refusal
          // is thrown into the SDK where nothing ever calls toLog() — so the identifiers an operator
          // needs are built and discarded, and the cheapest denials are the only ones reported.
          logSecurity: (event) => {
            console.error(JSON.stringify({ level: 'warn', channel: 'security', ...event }));
          },
          // And its operational twin, the same pair the revocation checker takes above. A spent
          // request budget is ordinary backend slowness reported by every outbound call, so filing it
          // on the security channel would put one record per slow request in front of the denials.
          logOperational: (event) => {
            console.error(JSON.stringify({ level: 'warn', channel: 'operational', ...event }));
          },
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
    // Said once at startup, loudly, because the placeholder wired as `auditEnqueue` above resolves
    // without recording anything and nothing else in a running process would reveal that.
    console.warn(
      JSON.stringify({
        level: 'warn',
        msg: 'audit enqueue is a placeholder: tool calls are dispatched WITHOUT a durable audit record. Do not deploy this build.',
      })
    );
    const listener = app.listen(config.port, () => {
      console.log(JSON.stringify({ level: 'info', msg: 'listening', port: config.port }));
    });
    const shutdown = () => {
      listener.close();
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    listener.once('error', confirmations.close);
    listener.once('close', () => {
      confirmations.close();
      process.removeListener('SIGINT', shutdown);
      process.removeListener('SIGTERM', shutdown);
    });
    return { listener, upstreamCredentialProvider, confirmations };
  } catch (error) {
    confirmations.close();
    throw error;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startServer().catch(() => {
    console.error(
      JSON.stringify({
        level: 'error',
        msg: 'Server startup failed; check configuration and Redis availability.',
      })
    );
    process.exitCode = 1;
  });
}
