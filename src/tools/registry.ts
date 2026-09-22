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
import { NO_SCOPE, mappedScopeFor, type ScopeDecision } from '../auth/scopes.ts';
import { McpError, type McpErrorLogPayload } from '../errors.ts';
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
  /**
   * Step 3's requirement for this tool, or the explicit opt-out. **Required, and DERIVED rather
   * than restated:** a shipped tool writes `TOOL_SCOPES.<its name>`, so the frozen map stays the
   * one hand-written statement of the tool-to-scope relation and this field cannot drift from it.
   * Writing the scope literal here instead would be a second statement of one relation, which is
   * this repository's most-recorded failure class.
   *
   * **Optional would reopen exactly the hole this closes.** An omitted field reads as "needs
   * nothing" and is indistinguishable from "nobody decided"; `NO_SCOPE` is a decision, and
   * `assertScopeDecision` refuses to register anything that has not made one.
   */
  readonly scope: ScopeDecision;
  readonly backing: BackingEndpoint;
  readonly handler: (request: ToolRequest) => ToolCallback<InputArgs>;
}

/**
 * Where a descriptor came from, which is the one thing that decides whether `NO_SCOPE` is
 * available to it.
 *
 * `shipped` is the list below, reviewed and deployed. `injected` is `RegistryConfig.extraTools`,
 * which is test-only and pinned as absent from the composition root. **A shipped tool may not opt
 * out of the scope step at all** — for it, the only acceptable declaration is the scope the frozen
 * map names, so the entry has to exist before the tool can register. That is what makes the
 * property structural rather than a declaration an author can write past.
 */
type ToolOrigin = 'shipped' | 'injected';

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
 * states the gap rather than omitting the step. A real audit implementation replaces it; nothing
 * else moves.
 *
 * **It returns a promise because the step has to be able to FAIL, and the call site awaits it.**
 * A durable enqueue is either a delivery to authenticated ingest or a write to the shared store,
 * and both are I/O that can refuse. A void-returning port cannot report that both paths failed, so
 * the step as declared could never close a request BEFORE upstream access — which is the whole
 * ordering guarantee this step exists to provide. The reason is that guarantee, not a lint rule.
 */
export type AuditEnqueue = (event: AuditEnqueueEvent) => Promise<void>;

/**
 * The placeholder described above, supplied by the composition root today. **It resolves
 * immediately and records nothing**, so dispatch proceeds with no audit record at all; the root
 * warns at startup while it is wired. Pinned by name in
 * `test/security/compositionRoot.test.ts`, so the day it leaves the root a gate notices.
 */
export const AUDIT_ENQUEUE_NOT_IMPLEMENTED: AuditEnqueue = () => Promise.resolve();

/**
 * What the security channel carries: the classes a refusal AT THE TRUST BOUNDARY is raised as.
 *
 * Narrower than `McpErrorLogPayload` deliberately. That union also carries the
 * `confirmation_required` variant, whose payload holds a `confirmation_token`, and the sink on the
 * far end serialises whatever it is handed — so a port typed on the whole union is a port that
 * writes a live confirmation token into an operator log the day a write tool refuses through here.
 */
export type RegistrySecurityEvent = Extract<
  McpErrorLogPayload,
  { class: 'unauthorized' | 'insufficient_scope' }
>;

/**
 * What the operational channel carries: a spent request budget is a timeout, which is a transport
 * failure rather than a decision anybody made about this caller.
 */
export type RegistryOperationalEvent = Extract<McpErrorLogPayload, { class: 'upstream_failure' }>;

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
  /**
   * The security channel, mirroring the one `src/auth/revocation.ts` takes. **Required**: a
   * dispatch denied at the trust boundary is the record an operator needs most, and an optional
   * port would let the step vanish from a composition with nothing to notice.
   *
   * Handed the error's **log** payload. The model-facing payload is a different object and carries
   * none of these identifiers — which is why a refusal that is merely thrown reports nothing at
   * all: the SDK never calls `toLog()`, so the payload was being constructed and discarded.
   */
  readonly logSecurity: (event: RegistrySecurityEvent) => void;
  /**
   * The operational channel, the twin `src/auth/revocation.ts` takes beside its security one.
   * **Required** for the same reason the security one is: an optional port lets the step vanish
   * from a composition with nothing to notice.
   *
   * The two are separated because a spent end-to-end budget is ordinary backend slowness — every
   * outbound call asks for what is left of the budget, so a slow upstream would otherwise write a
   * security record per request and bury the denials that carry a user, a client and a grant.
   * Transport and contract failure goes here; a dispatch actually denied goes to `logSecurity`.
   */
  readonly logOperational: (event: RegistryOperationalEvent) => void;
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

/**
 * Reporting must never change the refusal.
 *
 * A sink that throws would replace the `McpError` the caller is one statement away from raising
 * with whatever the sink threw — a bare `Error`, whose message the SDK renders toward the model,
 * and which a handler's `cause instanceof McpError` check does not match, so the cause class is
 * lost as well. A record nobody wrote is cheaper than a refusal nobody can read.
 */
function emit(report: () => void): void {
  try {
    report();
  } catch {
    // Deliberately swallowed: see above.
  }
}

/**
 * The one place a refusal raised here becomes a SECURITY record: a dispatch actually denied.
 *
 * Returned rather than thrown so every call site still reads as its own `throw` — and so the
 * reporting cannot drift from the raising: the error is constructed, reported and handed back in
 * one statement.
 *
 * **That is a convention here and a gate elsewhere.** `throw new McpError({...})` written directly
 * in this file typechecks and dispatches identically, so `test/security/compositionRoot.test.ts`
 * pins it instead, under `validate`: every `new McpError(` must sit inside one of these two
 * reporting calls, and the classes it may name are pinned there too. That second pin is what makes
 * the narrowing below sound — `toLog()` is typed over the whole taxonomy while each channel takes
 * a slice, and a runtime arm would be a branch the gate makes unreachable whose only behaviour
 * would be to drop a record. **Adding a class to a refusal here means giving it a channel.**
 */
function refuse(config: RegistryConfig, error: McpError): McpError {
  emit(() => {
    config.logSecurity(error.toLog() as RegistrySecurityEvent);
  });
  return error;
}

/**
 * The operational twin of `refuse`, for a transport or contract failure rather than a decision
 * about this caller. Same shape, same contract, a different channel — the line
 * `src/auth/revocation.ts` draws between its two sinks, and the one the authorization-order rule
 * states as "two different records".
 */
function reportOperational(config: RegistryConfig, error: McpError): McpError {
  emit(() => {
    config.logOperational(error.toLog() as RegistryOperationalEvent);
  });
  return error;
}

/** The transport handed nothing for this request, so the first two steps cannot be evidenced. */
function refuseUnauthorized(config: RegistryConfig, reason: string): McpError {
  return refuse(
    config,
    new McpError({
      class: 'unauthorized',
      reason,
      resourceMetadataUrl: config.resourceMetadataUrl,
    })
  );
}

/**
 * Step 3, re-checked here. Read off the **grant**, never the signed claim: the grant is what a
 * user narrowing a connection changes.
 *
 * The requirement is selected from `tool.name` — the DESCRIPTOR's name, fixed at registration —
 * never from anything the request carried. The transport selects its own from the `Mcp-Name`
 * routing header, which the caller chooses.
 *
 * **What this is NOT defending against, stated because the obvious reading is wrong:** a header
 * that names a different tool than the body does is refused by the SDK's protocol rung with a 400
 * before dispatch, pinned in `test/conformance/routingHeaders.test.ts`. What it IS defending
 * against is a door check that did not run — the transport takes its resolver as an OPTIONAL
 * field, and for most of this project's history the composition root did not pass it — plus
 * clients caching tool lists. Both are driven over the wire in `test/unit/transport/http.test.ts`.
 *
 * **Read off the DESCRIPTOR's declaration, not a map lookup by name.** A lookup answers `undefined`
 * for a name the map does not carry, which made the miss and the deliberate opt-out the same value
 * and let an unscoped tool dispatch unchecked. `assertScopeDecision` ran before this tool was
 * registered; its doc says what it refuses and why.
 */
function assertScope(
  config: RegistryConfig,
  authorization: RequestAuthorization,
  toolName: string,
  required: ScopeDecision
): void {
  if (required === NO_SCOPE) return;
  if (authorization.grant.scopes.includes(required)) return;
  throw refuse(
    config,
    new McpError({
      class: 'insufficient_scope',
      requiredScope: required,
      heldScopes: authorization.grant.scopes,
      resourceMetadataUrl: config.resourceMetadataUrl,
      userId: authorization.grant.subject,
      clientId: authorization.grant.clientId,
      grantId: authorization.grant.grantId,
      operation: toolName,
    })
  );
}

/**
 * The budget as a duration, computed at the instant it is asked for.
 *
 * Reported on the OPERATIONAL channel. Every tool asks for what is left of the budget on every
 * outbound call, so a slow backend refuses here routinely — that is a timeout, not an anomaly, and
 * filing it as one would put a record per request in front of the denials that name a user, a
 * client and a grant.
 */
function remainingBudgetMs(config: RegistryConfig, authorization: RequestAuthorization): number {
  const remaining = Math.floor(authorization.deadlineAt - authorization.now());
  if (!Number.isSafeInteger(remaining) || remaining <= 0) {
    throw reportOperational(
      config,
      new McpError({
        class: 'upstream_failure',
        statusClass: 'timeout',
        errorCode: 'request_deadline_exhausted',
        endpointClass: 'tool_dispatch',
        correlationId: authorization.correlationId,
        latencyMs: 0,
      })
    );
  }
  return remaining;
}

/** Step 4. Only reached by a descriptor that declares a credentialed backing endpoint. */
async function credentialFor(
  config: RegistryConfig,
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
    deadlineMs: remainingBudgetMs(config, authorization),
  });
}

/**
 * **The registration gate: a descriptor that has not made a scope decision never becomes
 * dispatchable.** Called for every tool before it is handed to the SDK, and again over the shipped
 * list at module load — so an unscoped shipped tool takes the process down on `npm start` rather
 * than on the first request that reaches it.
 *
 * It throws a plain `Error` on purpose. This is a composition defect, not a request outcome: there
 * is no caller to answer, nothing to report on the security channel, and no taxonomy class that
 * would be true of it. The taxonomy is for what happens TO a request.
 *
 * The three refusals, and why each is a refusal rather than a default:
 *
 * 1. The map names this tool and the descriptor declares something else — including `NO_SCOPE`.
 *    Two statements of one relation disagreeing is the failure class this whole shape exists to
 *    prevent, and the silent direction is always the enforcing copy differing from the readable
 *    one. Deriving the declaration (`TOOL_SCOPES.nutrition_lookup`) makes this unreachable; the
 *    check is what makes "derive it" enforced rather than advised.
 * 2. The map does not name a shipped tool. **This is the fail-open that was here**: tickets 25,
 *    30, 31, 32 and 48 each add a descriptor in a different branch, and the one that forgets the
 *    map entry used to dispatch with no scope check. `NO_SCOPE` does not rescue it, so the only
 *    way forward is the map entry.
 * 3. The map does not name an injected tool and it declares a scope anyway. That declaration is a
 *    tool-to-scope statement living outside the one place that relation is written, which is the
 *    thing being kept singular. A probe that needs a scope requirement takes a name the map
 *    already carries.
 */
export function assertScopeDecision(name: string, scope: ScopeDecision, origin: ToolOrigin): void {
  const mapped = mappedScopeFor(name);
  if (mapped !== undefined) {
    if (scope === mapped) return;
    throw new Error(
      `tool ${name} declares scope ${scope} and the frozen tool-to-scope map names ${mapped}`
    );
  }
  if (origin === 'shipped') {
    throw new Error(
      `tool ${name} is shipped and the frozen tool-to-scope map does not name it: add the entry there, which is the one statement of that relation`
    );
  }
  if (scope !== NO_SCOPE) {
    throw new Error(
      `injected tool ${name} declares scope ${scope} that the frozen tool-to-scope map does not name`
    );
  }
}

function registerOne<InputArgs extends StandardSchemaWithJSON>(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig,
  tool: ToolDescriptor<InputArgs>,
  origin: ToolOrigin
): void {
  // Before anything is handed to the SDK: a descriptor that fails here is never registered, so the
  // refusal is "cannot dispatch" rather than "dispatches and then refuses".
  assertScopeDecision(tool.name, tool.scope, origin);

  const dispatch = (async (args: unknown, callContext: unknown) => {
    // Steps 1 and 2, as evidence. The lookup is keyed on the object the transport created, so a
    // handler reached with an argument or a `_meta` blob shaped like an AuthInfo misses and
    // refuses — identity, not field equality, is what cannot be forged from request content.
    const authorization = config.authorizationFor(ctx.authInfo);
    if (authorization === undefined) {
      throw refuseUnauthorized(config, 'no live grant was established for this request');
    }

    assertScope(config, authorization, tool.name, tool.scope);

    const credential = await credentialFor(config, authorization, tool.backing);

    // Step 5, before dispatch and after the credential, as the order requires. AWAITED, so a
    // durable enqueue that fails closes the request before the TOOL's upstream call.
    //
    // Not before every upstream call, and the difference is worth stating: step 4 above is the
    // RFC 8693 exchange, which on a cache miss has already left through the one egress door by the
    // time this line runs. So a refused enqueue here closes a request that has already minted a
    // 120-second credential into the in-process cache with no durable record behind it. The order
    // is the one specified; the gap is recorded rather than worked around locally.
    //
    // See `AuditEnqueue`: what the deployed root supplies does nothing, and says so in its name.
    await config.auditEnqueue({
      tool: tool.name,
      correlationId: authorization.correlationId,
      grantId: authorization.grant.grantId,
    });

    const inner = tool.handler({
      nutrihelpApiBaseUrl: config.nutrihelpApiBaseUrl,
      remainingBudgetMs: () => remainingBudgetMs(config, authorization),
      correlationId: authorization.correlationId,
      credential,
    }) as (args: unknown, callContext: unknown) => unknown;

    return inner(args, callContext);
  }) as ToolCallback<InputArgs>;

  server.registerTool(tool.name, { ...tool.contract, inputSchema: tool.inputSchema }, dispatch);
}

/**
 * One shipped tool, as the two things that need it can both consume it: the fields the startup
 * check reads, and a registration already bound to its own descriptor.
 *
 * **The binding is what keeps this ONE list.** A descriptor's handler takes the arguments its own
 * schema infers, so `ToolDescriptor<StandardSchemaWithJSON>` is not a supertype of a concrete
 * descriptor and an array of them does not typecheck — which would have meant a list for the check
 * and a second list for the registration, two hand-maintained statements of one set. `shipped()`
 * closes over the descriptor while the generic is still known, so the array can be uniform.
 */
interface ShippedTool {
  readonly name: string;
  readonly scope: ScopeDecision;
  readonly register: (server: McpServer, ctx: McpRequestContext, config: RegistryConfig) => void;
}

function shipped<InputArgs extends StandardSchemaWithJSON>(
  tool: ToolDescriptor<InputArgs>
): ShippedTool {
  return {
    name: tool.name,
    scope: tool.scope,
    register: (server, ctx, config) => {
      registerOne(server, ctx, config, tool, 'shipped');
    },
  };
}

/** The tools this server ships. A descriptor reaches the trust boundary by being in this list. */
const SHIPPED_TOOLS: readonly ShippedTool[] = [shipped(nutritionLookup)];

/**
 * **The startup throw.** The core is stateless, so a server — and therefore every registration —
 * is built per request; there is no other moment in this design at which "startup" happens for the
 * registry. Importing this module is it. A shipped tool missing its map entry therefore fails
 * `npm start` outright instead of failing every request that reaches it, and it is pure
 * computation over two frozen constants, not I/O at module load.
 */
for (const tool of SHIPPED_TOOLS) {
  assertScopeDecision(tool.name, tool.scope, 'shipped');
}

export function registerTools(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig
): void {
  for (const tool of SHIPPED_TOOLS) {
    tool.register(server, ctx, config);
  }
  for (const tool of config.extraTools ?? []) {
    registerOne(server, ctx, config, tool, 'injected');
  }
}
