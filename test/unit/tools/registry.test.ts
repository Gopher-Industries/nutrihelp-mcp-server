import { unavailableConfirmations } from '../../support/confirmationFixture.ts';
/**
 * The dispatch wrapper: what runs between the transport's answer and a tool handler, and what it
 * refuses. Ticket 87.
 *
 * Driven against a recording server rather than over the wire, so each step can be removed one at
 * a time and the case that names it goes red on its own.
 */

import { describe, expect, it, vi } from 'vitest';
import { installUpstreamMock } from '../../support/upstreamMock.ts';
import type { AuthInfo, McpRequestContext, McpServer } from '@modelcontextprotocol/server';
import {
  AUDIT_ENQUEUE_NOT_IMPLEMENTED,
  assertScopeDecision,
  registerTools,
  type AuditEnqueueEvent,
  type RegistryConfig,
  type ToolRequest,
} from '../../../src/tools/registry.ts';
import { NO_SCOPE, type ScopeDecision } from '../../../src/auth/scopes.ts';
import { inputSchema } from '../../../src/tools/nutritionLookup.ts';
import type { AuthorizationLookup, RequestAuthorization } from '../../../src/transport/http.ts';
import type {
  UpstreamCredential,
  UpstreamCredentialRequest,
} from '../../../src/auth/upstreamToken.ts';
import { McpError, type McpErrorLogPayload } from '../../../src/errors.ts';
import { forgeActiveGrant } from '../../support/activeGrant.ts';
import {
  credentialedProbe,
  publicProbe,
  CREDENTIALED_TOOL_NAME,
  PUBLIC_TOOL_NAME,
} from '../../support/credentialedTool.ts';
import {
  CLIENT_ID,
  GRANT_A,
  NUTRIHELP_API_BASE_URL,
  RESOURCE_METADATA_URL,
  SCOPES,
  USER_A,
} from '../../support/testEnv.ts';

/** A dispatchable callback as the SDK would hold it, with both arguments forwarded. */
type Registered = (args: unknown, ctx: unknown) => unknown;

interface Recording {
  readonly server: McpServer;
  readonly registered: Map<string, Registered>;
}

function recordingServer(): Recording {
  const registered = new Map<string, Registered>();
  const server = {
    registerTool: (name: string, _config: unknown, cb: Registered): void => {
      registered.set(name, cb);
    },
  } as unknown as McpServer;
  return { server, registered };
}

const SUBJECT_TOKEN = 'the-inbound-access-token';
const CORRELATION_ID = 'registry-suite-correlation-id';

interface Harness {
  readonly config: RegistryConfig;
  readonly ctx: McpRequestContext;
  /** The object the transport would have created. Identity is the whole mechanism. */
  readonly authInfo: AuthInfo;
  readonly credentialRequests: UpstreamCredentialRequest[];
  readonly auditEnqueued: AuditEnqueueEvent[];
  /** Every refusal the registry reported on its security channel, in order. */
  readonly securityEvents: McpErrorLogPayload[];
  /**
   * And everything it reported on its operational channel. A SECOND collector, not a second field
   * on one list: two channels are only separated if a case can assert that one of them stayed
   * empty, and a shared collector would be satisfied by a registry that files every refusal as a
   * security anomaly.
   */
  readonly operationalEvents: McpErrorLogPayload[];
  advance(ms: number): void;
}

/**
 * A request as the transport hands it over: a branded grant, the real token, one absolute deadline
 * and a clock the case drives.
 */
function harness(
  options: {
    readonly scopes?: readonly string[];
    readonly budgetMs?: number;
    readonly bind?: 'this-request' | 'nothing';
  } = {}
): Harness {
  const credentialRequests: UpstreamCredentialRequest[] = [];
  const auditEnqueued: AuditEnqueueEvent[] = [];
  const securityEvents: McpErrorLogPayload[] = [];
  const operationalEvents: McpErrorLogPayload[] = [];
  let clock = 1_700_000_000_000;

  const authorization: RequestAuthorization = {
    grant: forgeActiveGrant({
      grantId: GRANT_A,
      scopes: options.scopes ?? [SCOPES.nutritionRead],
      subject: USER_A,
      clientId: CLIENT_ID,
      subjectToken: SUBJECT_TOKEN,
    }),
    subjectToken: SUBJECT_TOKEN,
    correlationId: CORRELATION_ID,
    deadlineAt: clock + (options.budgetMs ?? 30_000),
    now: () => clock,
    credentialFor: (request: UpstreamCredentialRequest): Promise<UpstreamCredential> => {
      credentialRequests.push(request);
      return Promise.resolve({
        accessToken: 'exchanged',
        grantId: request.grant.grantId,
        usableUntilMs: clock + 60_000,
      });
    },
  };

  const authInfo: AuthInfo = { token: 'a-digest', clientId: CLIENT_ID, scopes: [] };
  const bound = options.bind !== 'nothing';
  const lookup = new WeakMap<AuthInfo, RequestAuthorization>();
  if (bound) lookup.set(authInfo, authorization);

  const authorizationFor: AuthorizationLookup = (candidate) =>
    candidate === undefined ? undefined : lookup.get(candidate);

  return {
    config: {
      confirmations: unavailableConfirmations,
      logConfirmationAnomaly: () => undefined,
      nutrihelpApiBaseUrl: NUTRIHELP_API_BASE_URL,
      authorizationFor,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      auditEnqueue: (event: AuditEnqueueEvent): Promise<void> => {
        auditEnqueued.push(event);
        return Promise.resolve();
      },
      logSecurity: (event: McpErrorLogPayload): void => {
        securityEvents.push(event);
      },
      logOperational: (event: McpErrorLogPayload): void => {
        operationalEvents.push(event);
      },
      extraTools: [credentialedProbe],
    },
    ctx: { era: 'modern', authInfo },
    authInfo,
    credentialRequests,
    auditEnqueued,
    securityEvents,
    operationalEvents,
    advance: (ms: number): void => {
      clock += ms;
    },
  };
}

function dispatchable(h: Harness, name: string): Registered {
  const { server, registered } = recordingServer();
  registerTools(server, h.ctx, h.config);
  const callback = registered.get(name);
  if (callback === undefined) throw new Error(`${name} was never registered`);
  return callback;
}

describe('tool registration', () => {
  it('registers the nutrition lookup descriptor through the central dispatch path', () => {
    const registerTool = vi.fn();
    const server = { registerTool } as unknown as McpServer;
    const h = harness();

    registerTools(server, h.ctx, {
      confirmations: unavailableConfirmations,
      logConfirmationAnomaly: () => undefined,
      nutrihelpApiBaseUrl: NUTRIHELP_API_BASE_URL,
      authorizationFor: h.config.authorizationFor,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      auditEnqueue: AUDIT_ENQUEUE_NOT_IMPLEMENTED,
      logSecurity: h.config.logSecurity,
      logOperational: h.config.logOperational,
    });

    expect(registerTool).toHaveBeenCalledTimes(2);
    expect(registerTool).toHaveBeenCalledWith(
      'nutrition_lookup',
      expect.objectContaining({ inputSchema }),
      expect.any(Function)
    );
  });

  /**
   * **THE SKIP, REPORTED.** Step 5 is called in order and the value the deployed root supplies
   * does nothing, so a dispatch that reaches a tool has no durable audit record behind it. Asserted
   * rather than left out: a suite that simply omitted the step would look like a suite whose six
   * steps all passed.
   */
  it('calls step 5 and the deployed placeholder enqueues nothing', async () => {
    const h = harness();
    await dispatchable(h, CREDENTIALED_TOOL_NAME)({}, {});

    expect(
      h.auditEnqueued,
      'the step RAN — it is not omitted from the order, and ticket 34 changes one value to make it durable'
    ).toEqual([{ tool: CREDENTIALED_TOOL_NAME, correlationId: CORRELATION_ID, grantId: GRANT_A }]);
    await expect(
      AUDIT_ENQUEUE_NOT_IMPLEMENTED({
        tool: 'anything',
        correlationId: 'anything',
        grantId: 'anything',
      }),
      'and what the composition root supplies today accepts the event and does nothing with it. There is nowhere to look for the record, which is the point: a BYPASS of the audit rule rather than a fallback, named so it cannot read as satisfied'
    ).resolves.toBeUndefined();
  });

  /**
   * **THE STEP HAS TO BE ABLE TO FAIL, AND THE DISPATCH HAS TO STOP WHEN IT DOES.** The audit rule
   * is that a path skipping the durable enqueue is a bypass rather than a fallback, so a refused
   * enqueue must close the request BEFORE upstream access. A void-returning port could not express
   * that at all: whatever it did with a failure, the caller could not see it. Driven here against
   * the instrumented public probe, whose handler records that it ran.
   */
  it('closes the request when the durable enqueue refuses, before the handler runs', async () => {
    const h = harness();
    let handlerRan = false;
    const probe = {
      ...publicProbe,
      handler: (request: ToolRequest) => () => {
        handlerRan = true;
        return publicProbe.handler(request)();
      },
    };
    const { server, registered } = recordingServer();
    registerTools(server, h.ctx, {
      ...h.config,
      auditEnqueue: () => Promise.reject(new Error('neither ingest nor the shared store accepted')),
      extraTools: [probe],
    });

    await expect(
      registered.get(PUBLIC_TOOL_NAME)?.({}, {}),
      'a rejected enqueue reaches the caller, which is the whole reason the port returns a promise'
    ).rejects.toBeDefined();
    expect(
      handlerRan,
      'and step 6 never ran. Enqueue failure is a refusal, not a degraded mode: dispatching anyway would put a request upstream with no durable record behind it'
    ).toBe(false);
  });
});

/**
 * **A DISPATCH DENIED AT THE TRUST BOUNDARY IS A SECURITY RECORD, AND NOTHING ELSE MAKES ONE.**
 *
 * The refusals raised here carry `userId`, `clientId`, `grantId`, `heldScopes` and `operation` —
 * all of them log-side fields. Thrown into the SDK, nothing ever calls `toLog()`, so the payload
 * was built and discarded: the transport's cheaper denials were all reported and the dispatcher's
 * were invisible. Asserted per refusal path, because a report wired on one path reads exactly like
 * a report wired on all of them.
 */
describe('what a refusal at dispatch reports', () => {
  it('reports the unauthorized refusal with the reason on the log side', async () => {
    const h = harness({ bind: 'nothing' });

    await expect(dispatchable(h, 'nutrition_lookup')({ food: 'oats' }, {})).rejects.toBeDefined();

    expect(
      h.securityEvents,
      'exactly one record for one refusal, and it is the LOG payload: the model-facing payload carries none of these fields'
    ).toHaveLength(1);
    expect(h.securityEvents[0]).toMatchObject({
      class: 'unauthorized',
      reason: 'no live grant was established for this request',
    });
  });

  it('reports the insufficient-scope refusal with every identifier it constructed', async () => {
    const h = harness({ scopes: [] });

    await expect(dispatchable(h, 'nutrition_lookup')({ food: 'oats' }, {})).rejects.toBeDefined();

    expect(
      h.securityEvents[0],
      'the identifiers are the point. A refusal an operator cannot attribute to a user, a client and a grant is a refusal nobody can investigate'
    ).toEqual({
      class: 'insufficient_scope',
      requiredScope: SCOPES.nutritionRead,
      heldScopes: [],
      userId: USER_A,
      clientId: CLIENT_ID,
      grantId: GRANT_A,
      operation: 'nutrition_lookup',
    });
  });

  /**
   * **A SPENT BUDGET IS A TIMEOUT, AND A TIMEOUT IS NOT A SECURITY ANOMALY.** The error raised is
   * field-for-field the `OperationalEvent` shape `src/auth/revocation.ts` declares, and that module
   * draws the line three lines apart: transport and contract failures on one channel, a dispatch
   * actually denied on the other. Every tool asks for what is left of the budget on every outbound
   * call, so filing this as a denial puts one security record per slow backend request in front of
   * the refusals that carry a user, a client and a grant.
   */
  it('reports the spent-budget refusal on the OPERATIONAL channel, as the retryable class', async () => {
    const h = harness({ budgetMs: 1_000 });
    const call = dispatchable(h, CREDENTIALED_TOOL_NAME);
    h.advance(1_001);

    await expect(call({}, {})).rejects.toBeDefined();

    expect(h.operationalEvents[0]).toMatchObject({
      class: 'upstream_failure',
      errorCode: 'request_deadline_exhausted',
      correlationId: CORRELATION_ID,
    });
  });

  it('and the security channel stays EMPTY for it, so the two are separated by a gate', async () => {
    const h = harness({ budgetMs: 1_000 });
    const call = dispatchable(h, CREDENTIALED_TOOL_NAME);
    h.advance(1_001);

    await expect(call({}, {})).rejects.toBeDefined();

    expect(
      h.securityEvents,
      'the companion of the case above, and the half that fails if both channels are wired to one sink. Without it "operational" is a word in a comment: a registry reporting every refusal on both channels satisfies the assertion above and buries the denials just the same'
    ).toHaveLength(0);
    expect(
      h.operationalEvents,
      'control: the refusal WAS reported, so the emptiness above is about the channel rather than about a refusal nobody reported at all'
    ).toHaveLength(1);
  });

  it('reports NOTHING on either channel for a dispatch it served', async () => {
    const h = harness();

    await dispatchable(h, CREDENTIALED_TOOL_NAME)({}, {});

    expect(
      h.securityEvents,
      'the granting direction. Without it every assertion above is satisfied by a registry that reports on every dispatch, refused or not'
    ).toHaveLength(0);
    expect(h.operationalEvents, 'and the same for the operational channel').toHaveLength(0);
  });

  /**
   * **REPORTING MUST NEVER CHANGE THE REFUSAL.** The sink is supplied by the composition root and
   * runs inside the refusal path, so a sink that throws replaces the `McpError` the caller is one
   * statement from raising with a bare `Error` — whose message the SDK renders toward the model,
   * and which `nutritionLookup`'s `cause instanceof McpError` check does not match, so the cause
   * class is lost too. Driven per channel: a guard on one reads exactly like a guard on both.
   */
  it('raises the McpError even when the security sink throws', async () => {
    const h = harness({ scopes: [] });
    const { server, registered } = recordingServer();
    registerTools(server, h.ctx, {
      ...h.config,
      logSecurity: () => {
        throw new Error('the sink itself failed');
      },
    });

    await expect(
      registered.get('nutrition_lookup')?.({ food: 'oats' }, {}),
      'the taxonomy class, not whatever the sink threw'
    ).rejects.toBeInstanceOf(McpError);
  });

  it('raises the McpError even when the operational sink throws', async () => {
    const h = harness({ budgetMs: 1_000 });
    const { server, registered } = recordingServer();
    registerTools(server, h.ctx, {
      ...h.config,
      logOperational: () => {
        throw new Error('the sink itself failed');
      },
    });
    const call = registered.get(CREDENTIALED_TOOL_NAME);
    h.advance(1_001);

    await expect(
      call?.({}, {}),
      'the taxonomy class, not whatever the sink threw'
    ).rejects.toBeInstanceOf(McpError);
  });
});

describe('what dispatch requires before a handler runs', () => {
  /**
   * **The anti-forgery property, and it is object IDENTITY rather than field equality.** The model
   * chooses tool arguments, and a `_meta` blob decoded from the request body can carry any fields
   * it likes. This literal is field-for-field what the transport creates and is still not the key
   * the transport wrote, so the lookup misses and dispatch refuses.
   */
  it('misses on an AuthInfo-shaped literal that the transport never created', async () => {
    const h = harness();
    const forged: AuthInfo = { token: 'a-digest', clientId: CLIENT_ID, scopes: [] };

    expect(
      h.config.authorizationFor(forged),
      'identical fields, different object: a decoded argument cannot become a key in this map'
    ).toBeUndefined();
    expect(
      h.config.authorizationFor(h.authInfo),
      'control: the object the transport created does resolve, so the miss above is about identity rather than about an empty map'
    ).toBeDefined();

    const { server, registered } = recordingServer();
    registerTools(server, { era: 'modern', authInfo: forged }, h.config);
    const call = registered.get('nutrition_lookup');
    if (call === undefined) throw new Error('nutrition_lookup was never registered');

    await expect(
      call({ food: 'oats' }, {}),
      'and it refuses as UNAUTHORIZED specifically. `toBeInstanceOf(McpError)` was satisfied by any refusal at all, including one from a later step that would have refused this call anyway'
    ).rejects.toMatchObject({ class: 'unauthorized' });
  });

  it('refuses when the transport established nothing for this request', async () => {
    const h = harness({ bind: 'nothing' });

    await expect(
      dispatchable(h, 'nutrition_lookup')({ food: 'oats' }, {}),
      'the revocation opt-out binds no request, and a dispatch with nothing to read must refuse rather than proceed unauthenticated'
    ).rejects.toMatchObject({ class: 'unauthorized' });
  });

  it('re-checks the scope at dispatch, against the grant rather than the signed claim', async () => {
    const h = harness({ scopes: [] });

    let refusal: unknown;
    try {
      await dispatchable(h, 'nutrition_lookup')({ food: 'oats' }, {});
    } catch (cause: unknown) {
      refusal = cause;
    }

    expect(
      refusal,
      'clients cache tool lists, so the door check is not the last word — and the grant is what a user narrowing a connection changes'
    ).toBeInstanceOf(McpError);
    expect(
      (refusal as McpError).toModel(),
      'the model side names the scope so an assistant can ask for step-up. Read through toModel() rather than off the error: the init is private, so a property assertion here would pass on any insufficient_scope whatsoever'
    ).toMatchObject({ class: 'insufficient_scope', requiredScope: SCOPES.nutritionRead });
  });

  it('refuses once the one request budget is spent, without starting a fresh one', async () => {
    const h = harness({ budgetMs: 1_000 });
    const call = dispatchable(h, CREDENTIALED_TOOL_NAME);
    h.advance(1_001);

    await expect(call({}, {})).rejects.toMatchObject({ class: 'upstream_failure' });
    expect(
      h.credentialRequests,
      'and it refuses BEFORE step 4: a stage with no budget left must not go out at all'
    ).toHaveLength(0);
  });
});

describe('step 4 is per tool and lazy', () => {
  /**
   * **THE ABSENCE HAS TO BE PAIRED WITH A REACHED-THE-HANDLER ASSERTION.** `credentialRequests`
   * is empty when a public tool skipped exchange — and equally empty when the identity lookup or
   * the scope check refused before step 4 was ever considered. The prose used to say "that is past
   * step 4" and nothing asserted it.
   */
  it('never mints a credential for a public backing endpoint', async () => {
    const h = harness();
    const upstream = installUpstreamMock([]);
    upstream.route({ path: '/api/fooddata/search?query=oats', status: 503, body: 'unavailable' });

    let refusal: unknown;
    try {
      await dispatchable(h, 'nutrition_lookup')({ food: 'oats' }, {});
    } catch (cause: unknown) {
      refusal = cause;
    } finally {
      await upstream.restore();
    }

    expect(refusal).toMatchObject({ code: -32004 });
    expect(
      h.operationalEvents[0],
      'and it failed inside the TOOL, at its own outbound call: that error code is minted by nutrition_lookup and by nothing before it, so the dispatch really did get past steps 1 to 5'
    ).toMatchObject({ class: 'upstream_failure' });
    expect(
      h.auditEnqueued,
      'and step 5 ran for it, which is the last thing before the handler'
    ).toHaveLength(1);
    expect(
      h.credentialRequests,
      'nutrition_lookup skips exchange and calls with no credential. Minting one here would exchange a user-scoped credential for a call that never presents it'
    ).toHaveLength(0);
  });

  /**
   * The registry raises a spent end-to-end budget as `request_deadline_exhausted`. The tool's own
   * `catch` used to convert every failure to the generic nutrition-lookup 5xx, which reports the
   * wrong component to an operator and hides the one failure a longer deadline would fix.
   */
  it('lets the tool surface a spent budget as the deadline class, not as its own 5xx', async () => {
    const h = harness({ budgetMs: 1_000 });
    const call = dispatchable(h, 'nutrition_lookup');
    h.advance(1_001);

    let refusal: unknown;
    try {
      await call({ food: 'oats' }, {});
    } catch (cause: unknown) {
      refusal = cause;
    }

    expect(
      h.operationalEvents[0],
      'the cause class is preserved through the tool boundary. Converted, this reads as nutrition_lookup_failed and an operator goes looking at the backend'
    ).toMatchObject({ class: 'upstream_failure', errorCode: 'request_deadline_exhausted' });
    expect(refusal).toMatchObject({ code: -32004 });
  });

  it('mints one for a credentialed backing endpoint, carrying the branded grant whole', async () => {
    const h = harness();

    const result = (await dispatchable(h, CREDENTIALED_TOOL_NAME)({}, {})) as {
      structuredContent: { credentialed: boolean; grant_id: string };
    };

    expect(h.credentialRequests).toHaveLength(1);
    const request = h.credentialRequests[0];
    expect(request?.subjectToken, 'the inbound token, which only this path can reach').toBe(
      SUBJECT_TOKEN
    );
    expect(
      request?.grant,
      'the grant object itself, not a reassembly of its fields: decomposing it drops the brand and the token digest the minter refuses a mismatch on'
    ).toBe(h.config.authorizationFor(h.authInfo)?.grant);
    expect(request?.correlationId).toBe(CORRELATION_ID);
    expect(
      request?.deadlineMs,
      'a slice of the one budget, never a fresh full copy of it'
    ).toBeLessThanOrEqual(30_000);
    expect(result.structuredContent.credentialed).toBe(true);
    expect(result.structuredContent.grant_id).toBe(GRANT_A);
  });

  it('hands the handler the budget as a function, read at the moment of the call', async () => {
    const h = harness({ budgetMs: 10_000 });
    let seen: ToolRequest | undefined;
    const probe = {
      ...credentialedProbe,
      name: 'budget_probe',
      handler: (request: ToolRequest) => () => {
        seen = request;
        return { content: [{ type: 'text' as const, text: '{}' }] };
      },
    };
    const { server, registered } = recordingServer();
    registerTools(server, h.ctx, { ...h.config, extraTools: [probe] });

    await registered.get('budget_probe')?.({}, {});
    h.advance(4_000);

    expect(
      seen?.remainingBudgetMs(),
      'captured as a number it would still say 10000 here. Read late, it says what is actually left — and the clock is fully driven by this case, so the answer is exactly 6000 rather than at most it'
    ).toBe(6_000);
    expect(seen?.correlationId).toBe(CORRELATION_ID);
  });
});

/**
 * **A REGISTERED DESCRIPTOR CANNOT REACH DISPATCH WITHOUT A SCOPE DECISION.**
 *
 * The registry used to select the requirement by looking the descriptor's name up in the frozen
 * map and returning early on a miss. At the transport that default is honest — the name arrives in
 * a routing header and may be a typo — but here the name comes off a descriptor that IS registered
 * and IS dispatchable, so a miss meant nobody had scoped the tool, and the tool dispatched with no
 * scope check at all. It failed OPEN.
 *
 * Nothing shipped broken: `nutrition_lookup` is in the map, and a unit scan pinned the property.
 * The scan is a test, though, and tickets 25, 30, 31, 32 and 48 each add a descriptor in a
 * different branch. These cases are about the mechanism that makes a missed entry impossible
 * rather than merely noticed.
 */
describe('the scope decision every descriptor must carry', () => {
  /** What an author writes today, with a name the frozen map carries. */
  it.each([
    { label: 'the shipped tool', name: 'nutrition_lookup', scope: SCOPES.nutritionRead },
    { label: 'a tool the map names', name: 'record_meal', scope: SCOPES.meallogWrite },
  ])('accepts $label declaring exactly what the map names', ({ name, scope }) => {
    expect(() => {
      assertScopeDecision(name, scope, 'shipped');
    }).not.toThrow();
    expect(() => {
      assertScopeDecision(name, scope, 'injected');
    }).not.toThrow();
  });

  it('accepts an injected descriptor that declares the opt-out', () => {
    expect(() => {
      assertScopeDecision('credentialed_probe', NO_SCOPE, 'injected');
    }, 'a test probe saying it needs no scope BY DESIGN. This is the case the opt-out exists for, and it is a declaration rather than an omission').not.toThrow();
  });

  /** The fail-open itself: a shipped tool nobody put in the map. */
  it.each<{ label: string; scope: ScopeDecision }>([
    { label: 'declaring the opt-out', scope: NO_SCOPE },
    { label: 'declaring a scope of its own', scope: SCOPES.mealplanRead },
  ])('refuses to register an unmapped SHIPPED tool $label', ({ scope }) => {
    expect(() => {
      assertScopeDecision('get_meal_plan_v2', scope, 'shipped');
    }, 'the opt-out does not rescue a shipped tool and a scope written here does not either: the map entry is the only way forward, which is what keeps that relation written in one place').toThrow(
      /frozen tool-to-scope map/
    );
  });

  it('refuses a mapped tool that declares the opt-out', () => {
    expect(() => {
      assertScopeDecision('record_meal', NO_SCOPE, 'injected');
    }, 'the map says meallog:write. A descriptor opting out of it would dispatch a write tool with no scope check, past a map entry that reads as if it were enforcing').toThrow(
      /meallog:write/
    );
  });

  it('refuses a mapped tool that declares a DIFFERENT scope', () => {
    expect(() => {
      assertScopeDecision('record_meal', SCOPES.nutritionRead, 'injected');
    }, 'two statements of one relation disagreeing. Deriving the declaration from the map makes this unreachable; this check is what makes deriving it enforced rather than advised').toThrow(
      /meallog:write/
    );
  });

  it('refuses an injected tool that declares a scope the map does not name', () => {
    expect(() => {
      assertScopeDecision('rogue_probe', SCOPES.nutritionRead, 'injected');
    }, 'a tool-to-scope statement living outside the one place that relation is written. A probe needing a requirement takes a name the map already carries').toThrow(
      /does not name/
    );
  });

  it.each(['constructor', '__proto__', 'toString'])(
    'reads the inherited key %s as unmapped rather than as a scope off the prototype',
    (name) => {
      expect(() => {
        assertScopeDecision(name, NO_SCOPE, 'injected');
      }).not.toThrow();
      expect(() => {
        assertScopeDecision(name, NO_SCOPE, 'shipped');
      }).toThrow();
    }
  );

  /**
   * **THE END-TO-END DIRECTION, and the one that matters: it never becomes dispatchable.** A
   * descriptor whose decision is missing is refused at registration, so there is no callback to
   * call — rather than a callback that refuses once someone calls it.
   */
  it('registers nothing for a descriptor with no scope decision at all', () => {
    const h = harness();
    const { server, registered } = recordingServer();
    // The field is required, so "missing" is only reachable through a cast — which is exactly the
    // shape a new descriptor takes while it is being written.
    const undecided = {
      ...publicProbe,
      name: 'undecided_probe',
      scope: undefined,
    } as unknown as NonNullable<RegistryConfig['extraTools']>[number];

    expect(() => {
      registerTools(server, h.ctx, { ...h.config, extraTools: [undecided] });
    }).toThrow(/undecided_probe/);
    expect(
      registered.get('undecided_probe'),
      'not registered, so there is no dispatch path to refuse on. The shipped tool registered before it, which is what says the throw stopped THIS descriptor rather than the whole call'
    ).toBeUndefined();
    expect(registered.get('nutrition_lookup')).toBeDefined();
  });

  /**
   * And the granting half, so the cases above are not satisfied by a check that refuses
   * everything: the declaration on the descriptor is what the dispatch-time check reads.
   */
  it('enforces the declared scope at dispatch, and permits the call that holds it', async () => {
    const scoped = { ...publicProbe, name: 'record_meal', scope: SCOPES.meallogWrite };

    const denied = harness({ scopes: [SCOPES.nutritionRead] });
    const deniedServer = recordingServer();
    registerTools(deniedServer.server, denied.ctx, { ...denied.config, extraTools: [scoped] });
    await expect(
      deniedServer.registered.get('record_meal')?.({}, {}),
      'the grant carries nutrition:read and the descriptor declares meallog:write'
    ).rejects.toMatchObject({ class: 'insufficient_scope' });

    const permitted = harness({ scopes: [SCOPES.meallogWrite] });
    const permittedServer = recordingServer();
    registerTools(permittedServer.server, permitted.ctx, {
      ...permitted.config,
      extraTools: [scoped],
    });
    await expect(
      permittedServer.registered.get('record_meal')?.({}, {}),
      'and the same descriptor dispatches for a grant that holds it. Without this the cases above are satisfied by a registry that refuses every call'
    ).resolves.toBeDefined();
  });
});
