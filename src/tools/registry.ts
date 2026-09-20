/**
 * The single dispatch path for every tool, and the trust boundary: an untrusted model chooses both
 * the operation and its arguments here.
 *
 * `server.ts` registers tools by calling `registerTools`; it never imports a tool module. Every
 * registered handler is wrapped so the last four steps of the mandatory order run before it — the
 * first two ran at the transport and arrive as evidence rather than as a claim.
 */

import type { McpServer, McpRequestContext, ToolCallback } from '@modelcontextprotocol/server';
import type { StandardSchemaWithJSON } from '@modelcontextprotocol/server';
import type { AuthorizationLookup, RequestAuthorization } from '../transport/http.ts';
import type { UpstreamCredential } from '../auth/upstreamToken.ts';
import { requiredScopeFor } from '../auth/scopes.ts';
import { McpError } from '../errors.ts';
// 1. Import the plain descriptor package directly from the tool file
import { descriptor as nutritionLookup } from './nutritionLookup.ts';

/**
 * Whether a tool's backing endpoint needs the exchanged credential.
 *
 * **A public backing endpoint skips exchange and calls with no credential**, and `tools/list`
 * never exchanges. So step 4 is per tool, consumed lazily at dispatch — minting eagerly in the
 * transport would exchange a credential for every listing and for every public read, widening the
 * blast radius of a compromise for calls that never present one.
 */
export type BackingEndpoint = 'public' | 'credentialed';

/**
 * What one dispatch hands a tool handler. Built here, per request, after the checks above it have
 * passed — so a handler cannot be constructed without them having run.
 */
export interface ToolRequest {
  readonly nutrihelpApiBaseUrl: string;
  /**
   * What is LEFT of the one end-to-end budget, read **at the moment of the outbound call** rather
   * than captured at registration. A stage handed a number computed earlier is a stage spending a
   * budget that has already been partly spent. Throws the retryable class when nothing is left.
   */
  readonly remainingBudgetMs: () => number;
  /** The transport's identifier for this request. Never minted here. */
  readonly correlationId: string;
  /** Step 4's result, `undefined` for a public backing endpoint. */
  readonly credential: UpstreamCredential | undefined;
}

/** A tool as this module consumes it. Generic so `registerTool` keeps its schema inference. */
export interface ToolDescriptor<InputArgs extends StandardSchemaWithJSON> {
  readonly name: string;
  readonly contract: {
    readonly title: string;
    readonly description: string;
    readonly outputSchema: StandardSchemaWithJSON;
  };
  readonly inputSchema: InputArgs;
  readonly backing: BackingEndpoint;
  readonly handler: (request: ToolRequest) => ToolCallback<InputArgs>;
}

/** What step 5 would durably enqueue. Opaque references only; never arguments or a token. */
export interface AuditEnqueueEvent {
  readonly tool: string;
  readonly correlationId: string;
  readonly grantId: string;
}

/**
 * Step 5 of the mandatory order, as a port.
 *
 * **It is a HOLE, and it is named so it cannot read as satisfied.** `src/audit/logger.ts` is in
 * the plan's module list and has never been written, and the audit rule is explicit that a path
 * skipping the durable enqueue is **a bypass, not a fallback**. The step is therefore declared,
 * called in order, and fulfilled today by `AUDIT_ENQUEUE_NOT_IMPLEMENTED` — a composition that
 * states the gap rather than omitting the step. Ticket 34 replaces it; nothing else moves.
 */
export type AuditEnqueue = (event: AuditEnqueueEvent) => void;

/**
 * The placeholder described above, supplied by the composition root today. Pinned by name in
 * `test/security/compositionRoot.test.ts`, so the day it leaves the root a gate notices.
 */
export const AUDIT_ENQUEUE_NOT_IMPLEMENTED: AuditEnqueue = () => undefined;

export interface RegistryConfig {
  readonly nutrihelpApiBaseUrl: string;
  /** Step 5. **Required**: optional would let the step vanish with nothing to notice it. */
  readonly auditEnqueue: AuditEnqueue;
  /**
   * How dispatch reaches what the transport established for this request. **Required**: without it
   * every tool refuses, which is the correct direction — an omitted lookup must not read as "this
   * request needed no authorization".
   */
  readonly authorizationFor: AuthorizationLookup;
  /** Pointer carried by the refusals raised here, derived from the served document. */
  readonly resourceMetadataUrl: string;
  /**
   * Registered alongside the built-in set. **The only reason this exists:** no shipped tool has a
   * credentialed backing endpoint yet, so without an injected one every assertion about step 4
   * would be vacuous — a suite proving a credential is never minted, against a registry in which
   * nothing could mint one. Production passes nothing.
   */
  readonly extraTools?: readonly ToolDescriptor<StandardSchemaWithJSON>[];
}

/** The transport handed nothing for this request, so the first two steps cannot be evidenced. */
function refuseUnauthorized(config: RegistryConfig, reason: string): McpError {
  return new McpError({
    class: 'unauthorized',
    reason,
    resourceMetadataUrl: config.resourceMetadataUrl,
  });
}

/**
 * Step 3, re-checked here because clients cache tool lists and the transport's check read the
 * routing headers rather than the body. Read off the **grant**, never the signed claim: the grant
 * is what a user narrowing a connection changes.
 */
function assertScope(
  config: RegistryConfig,
  authorization: RequestAuthorization,
  toolName: string
): void {
  const required = requiredScopeFor({ method: 'tools/call', name: toolName });
  if (required === undefined) return;
  if (authorization.grant.scopes.includes(required)) return;
  throw new McpError({
    class: 'insufficient_scope',
    requiredScope: required,
    heldScopes: authorization.grant.scopes,
    resourceMetadataUrl: config.resourceMetadataUrl,
    userId: authorization.grant.subject,
    clientId: authorization.grant.clientId,
    grantId: authorization.grant.grantId,
    operation: toolName,
  });
}

/** The budget as a duration, computed at the instant it is asked for. */
function remainingBudgetMs(authorization: RequestAuthorization, correlationId: string): number {
  const remaining = Math.floor(authorization.deadlineAt - authorization.now());
  if (!Number.isSafeInteger(remaining) || remaining <= 0) {
    throw new McpError({
      class: 'upstream_failure',
      statusClass: 'timeout',
      errorCode: 'request_deadline_exhausted',
      endpointClass: 'tool_dispatch',
      correlationId,
      latencyMs: 0,
    });
  }
  return remaining;
}

/** Step 4. Only reached by a descriptor that declares a credentialed backing endpoint. */
async function credentialFor(
  authorization: RequestAuthorization,
  backing: BackingEndpoint
): Promise<UpstreamCredential | undefined> {
  if (backing === 'public') return undefined;
  return authorization.credentialFor({
    subjectToken: authorization.subjectToken,
    // Carried whole. Decomposing it into strings loses the brand and the token digest, which are
    // together what let the minter refuse a grant paired with a different token.
    grant: authorization.grant,
    correlationId: authorization.correlationId,
    deadlineMs: remainingBudgetMs(authorization, authorization.correlationId),
  });
}

function registerOne<InputArgs extends StandardSchemaWithJSON>(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig,
  tool: ToolDescriptor<InputArgs>
): void {
  const dispatch = (async (args: unknown, callContext: unknown) => {
    // Steps 1 and 2, as evidence. The lookup is keyed on the object the transport created, so a
    // handler reached with an argument or a `_meta` blob shaped like an AuthInfo misses and
    // refuses — identity, not field equality, is what cannot be forged from request content.
    const authorization = config.authorizationFor(ctx.authInfo);
    if (authorization === undefined) {
      throw refuseUnauthorized(config, 'no live grant was established for this request');
    }

    assertScope(config, authorization, tool.name);

    const credential = await credentialFor(authorization, tool.backing);

    // Step 5, before dispatch and after the credential, as the order requires. See `AuditEnqueue`:
    // what the deployed root supplies here does nothing, and says so in its name.
    config.auditEnqueue({
      tool: tool.name,
      correlationId: authorization.correlationId,
      grantId: authorization.grant.grantId,
    });

    const inner = tool.handler({
      nutrihelpApiBaseUrl: config.nutrihelpApiBaseUrl,
      remainingBudgetMs: () => remainingBudgetMs(authorization, authorization.correlationId),
      correlationId: authorization.correlationId,
      credential,
    }) as (args: unknown, callContext: unknown) => unknown;

    return inner(args, callContext);
  }) as ToolCallback<InputArgs>;

  server.registerTool(tool.name, { ...tool.contract, inputSchema: tool.inputSchema }, dispatch);
}

export function registerTools(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig
): void {
  registerOne(server, ctx, config, nutritionLookup);
  for (const tool of config.extraTools ?? []) {
    registerOne(server, ctx, config, tool);
  }
}
