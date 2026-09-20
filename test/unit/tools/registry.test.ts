/**
 * The dispatch wrapper: what runs between the transport's answer and a tool handler, and what it
 * refuses. Ticket 87.
 *
 * Driven against a recording server rather than over the wire, so each step can be removed one at
 * a time and the case that names it goes red on its own.
 */

import { describe, expect, it, vi } from 'vitest';
import type { AuthInfo, McpRequestContext, McpServer } from '@modelcontextprotocol/server';
import {
  AUDIT_ENQUEUE_NOT_IMPLEMENTED,
  registerTools,
  type AuditEnqueueEvent,
  type RegistryConfig,
  type ToolRequest,
} from '../../../src/tools/registry.ts';
import { inputSchema } from '../../../src/tools/nutritionLookup.ts';
import type { AuthorizationLookup, RequestAuthorization } from '../../../src/transport/http.ts';
import type {
  UpstreamCredential,
  UpstreamCredentialRequest,
} from '../../../src/auth/upstreamToken.ts';
import { McpError } from '../../../src/errors.ts';
import { forgeActiveGrant } from '../../support/activeGrant.ts';
import { credentialedProbe, CREDENTIALED_TOOL_NAME } from '../../support/credentialedTool.ts';
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
      nutrihelpApiBaseUrl: NUTRIHELP_API_BASE_URL,
      authorizationFor,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      auditEnqueue: (event: AuditEnqueueEvent) => auditEnqueued.push(event),
      extraTools: [credentialedProbe],
    },
    ctx: { era: 'modern', authInfo },
    authInfo,
    credentialRequests,
    auditEnqueued,
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
      nutrihelpApiBaseUrl: NUTRIHELP_API_BASE_URL,
      authorizationFor: h.config.authorizationFor,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      auditEnqueue: AUDIT_ENQUEUE_NOT_IMPLEMENTED,
    });

    expect(registerTool).toHaveBeenCalledTimes(1);
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
    expect(() => {
      AUDIT_ENQUEUE_NOT_IMPLEMENTED({
        tool: 'anything',
        correlationId: 'anything',
        grantId: 'anything',
      });
    }, 'and what the composition root supplies today accepts the event and does nothing with it. There is nowhere to look for the record, which is the point: a BYPASS of the audit rule rather than a fallback, named so it cannot read as satisfied').not.toThrow();
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

    await expect(call({ food: 'oats' }, {})).rejects.toBeInstanceOf(McpError);
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
  it('never mints a credential for a public backing endpoint', async () => {
    const h = harness();

    // Reaches the handler, which fails at the (unmocked) upstream call — that is past step 4.
    await expect(dispatchable(h, 'nutrition_lookup')({ food: 'oats' }, {})).rejects.toBeDefined();

    expect(
      h.credentialRequests,
      'nutrition_lookup skips exchange and calls with no credential. Minting one here would exchange a user-scoped credential for a call that never presents it'
    ).toHaveLength(0);
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
      'captured as a number it would still say 10000 here. Read late, it says what is actually left'
    ).toBeLessThanOrEqual(6_000);
    expect(seen?.correlationId).toBe(CORRELATION_ID);
  });
});
