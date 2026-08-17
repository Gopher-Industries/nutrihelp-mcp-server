/**
 * Operator codes distinguish failure classes; none of them may carry token contents.
 * jose hangs the decoded payload on the rejection and on its `cause`.
 */

import { inspect } from 'node:util';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  corruptSignature,
  createTestKeyPair,
  makePlatformToken,
  makeToken,
  PLATFORM_ACCESS_TOKEN_TYPE,
  type TestKeyPair,
} from '../../../scripts/makeToken.ts';
import {
  closeLocalDispatcher,
  listTools,
  startTestServer,
  type TestServer,
  type TestServerOptions,
} from '../../support/mcpClient.ts';
import {
  installUpstreamMock,
  type JwksOutcome,
  type UpstreamMock,
} from '../../support/upstreamMock.ts';
import { expectNotAnAuthChallenge, expectUnauthorizedChallenge } from '../../support/assertions.ts';
import {
  ALL_SCOPES,
  MCP_EXPECTED_ISSUER,
  MCP_JWKS_URL,
  MCP_RESOURCE_IDENTIFIER,
  SCOPES,
  USER_A,
} from '../../support/testEnv.ts';

/**
 * Values chosen so that finding any of them anywhere is unambiguous. Every one is a field the
 * decoded payload carries, and every one identifies a person, an assistant or a grant.
 */
const SENTINELS = {
  sub: 'sentinel-subject-8f21a',
  scope: 'sentinel-scope-8f21a',
  clientId: 'https://sentinel-client-8f21a.test/mcp-client.json',
  grantId: 'sentinel-grant-8f21a',
  jti: 'sentinel-jti-8f21a',
} as const;

const SENTINEL_VALUES = Object.values(SENTINELS);

let trustedKey: TestKeyPair;
let foreignKey: TestKeyPair;
let platformSecret: Uint8Array;
let server: TestServer;
let upstream: UpstreamMock;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  foreignKey = await createTestKeyPair('a-key-that-is-never-published');
  platformSecret = new Uint8Array(32);
  crypto.getRandomValues(platformSecret);
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  server = await startTestServer();
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

/** A token carrying the sentinel identity, so any leak is attributable. `overrides` is what makes
 *  it rejectable. */
function sentinelToken(overrides: Partial<Parameters<typeof makeToken>[0]> = {}): Promise<string> {
  return makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SENTINELS.scope],
    sub: SENTINELS.sub,
    clientId: SENTINELS.clientId,
    grantId: SENTINELS.grantId,
    jti: SENTINELS.jti,
    ...overrides,
  });
}

function reportedCodes(): string[] {
  return server.errors.map((error) => error.message);
}

/**
 * Every rejection shape, as ONE table that all three tests below consume.
 *
 * It was three independently maintained lists — a `causes` array, a `rejectableTokens()` function
 * and a labels-only constant that only its own floor test referenced. That is two hand-maintained
 * copies of one set plus a floor guarding neither: deleting a shape left the floor green and the
 * count assertions simply adapted to the smaller set, so both anti-vacuity guards passed over a
 * suite that had quietly shrunk.
 */
const REJECTION_SHAPES: readonly {
  readonly label: string;
  readonly make: () => Promise<string>;
}[] = [
  { label: 'expired', make: () => sentinelToken({ exp: '-5m' }) },
  {
    label: 'wrong audience',
    make: () => sentinelToken({ aud: 'https://api.nutrihelp.test/other' }),
  },
  { label: 'wrong issuer', make: () => sentinelToken({ iss: 'https://elsewhere.test' }) },
  { label: 'wrong type', make: () => sentinelToken({ type: PLATFORM_ACCESS_TOKEN_TYPE }) },
  { label: 'bad signature', make: async () => corruptSignature(await sentinelToken()) },
  { label: 'unpublished key', make: () => sentinelToken({ key: foreignKey }) },
];

/**
 * Render an error and everything reachable from it. NOT
 * `JSON.stringify(error, Object.getOwnPropertyNames(error))`: the array argument is a property
 * allowlist applied at EVERY nesting level, so a payload's own children are dropped even when
 * `payload` itself is named. Measured on Node 24 — that spelling could see neither
 * `error.payload.sub` nor `error.cause.payload.sub`, which is both directions of the leak this
 * assertion exists to catch. `inspect` walks the whole graph.
 */
function renderWholeError(error: Error): string {
  return inspect(error, { depth: null, showHidden: true });
}

describe('what a rejected credential is reported as', () => {
  it('reports an expired token and a wrong-audience token as two different things', async () => {
    const expired = await sentinelToken({ exp: '-5m' });
    await listTools(server, expired);
    const afterExpired = reportedCodes();

    const wrongAudience = await sentinelToken({
      aud: 'https://api.nutrihelp.test/some-other-resource',
    });
    await listTools(server, wrongAudience);
    const afterBoth = reportedCodes();

    expect(afterExpired, 'the expired token produced exactly one report').toHaveLength(1);
    const expiredCode = afterExpired[0];
    const audienceCode = afterBoth[1];

    expect(expiredCode).toBeDefined();
    expect(audienceCode).toBeDefined();
    expect(
      audienceCode,
      'a wrong audience is misconfiguration or replay and wants a different alert from a token that simply aged out. One flat code for both makes that distinction unrecoverable from logs'
    ).not.toBe(expiredCode);
  });

  /**
   * The full set, asserted as a set. Distinctness matters more than any individual spelling: two
   * causes sharing a code cannot be told apart afterwards, and the challenge a client sees is
   * identical for all of them by design.
   */
  it('reports each distinguishable cause distinctly', async () => {
    const observed = new Map<string, string>();
    for (const shape of REJECTION_SHAPES) {
      const before = server.errors.length;
      await listTools(server, await shape.make());
      const fresh = reportedCodes().slice(before);

      expect(fresh, `${shape.label}: reported exactly once`).toHaveLength(1);
      observed.set(shape.label, fresh[0] ?? '');
    }

    expect(
      new Set(observed.values()).size,
      `every cause must be separable in logs. Observed: ${JSON.stringify([...observed])}`
    ).toBe(REJECTION_SHAPES.length);
  });

  /**
   * An unpublished key identifier is a statement about the TOKEN, not about the key set: the set
   * was reachable, it answered, and it did not contain that key. So this is a 401 with a challenge
   * like every other credential refusal, and it gets its own code only so an operator can tell a
   * stale key set apart from a forged one.
   *
   * The code is pinned exactly rather than matched against `/key/`. A loose pattern here read as if
   * it covered the key-set cause class while asserting the credential side, which is what let the
   * genuine key-set behaviour ship with no assertion at all — the describe block below is where
   * that case lives.
   */
  it('reports an unpublished key identifier distinctly from the other credential failures', async () => {
    const before = server.errors.length;
    const response = await listTools(server, await sentinelToken({ key: foreignKey }));
    const [code] = reportedCodes().slice(before);

    expect(code, 'the operator code names the key the token asked for, and nothing else').toBe(
      'unauthorized.unknown_key'
    );
    expect(
      response.status,
      'and the answer is the ordinary credential refusal: the key set answered, so this is the token being wrong rather than the set being unavailable'
    ).toBe(401);
    expectUnauthorizedChallenge(response, 'a token naming an unpublished key');
  });

  it('reports the platform HS256 token as refused, not as a claim problem', async () => {
    const before = server.errors.length;
    await listTools(server, await makePlatformToken({ secret: platformSecret, userId: USER_A }));
    const [code] = reportedCodes().slice(before);

    expect(
      code,
      'the algorithm pin refuses it before any claim is read, so the code must not name a claim: a claim code here would mean the token had been decoded and its claims compared'
    ).not.toMatch(/issuer|audience|expired|type/);
    expect(
      code,
      'and it is the generic refusal rather than a bespoke code, because there is nothing more specific to say about a token signed with an algorithm this server does not accept'
    ).toBe('unauthorized.token_rejected');
  });

  /**
   * The granting direction. Every assertion above counts reports, and an endpoint that reported on
   * every request — including served ones — would satisfy them while making the log useless.
   */
  it('reports nothing at all for a credential that verifies', async () => {
    const good = await makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: ALL_SCOPES,
      sub: USER_A,
    });

    const response = await listTools(server, good);

    expect(response.rpc?.id, 'the request was served').toBe(1);
    expect(response.status, 'and not refused').not.toBe(401);
    expect(
      reportedCodes(),
      'a successful authorization is not an operator signal, and reporting one would bury the refusals'
    ).toEqual([]);
  });
});

/**
 * The other cause class, and the one this file had no assertion for at all.
 *
 * A key set that cannot be consulted says nothing about the credential that was presented. Answering
 * 401 with a Bearer challenge asserts the token was bad and sends every client into
 * refresh-and-retry against the one component already failing — on a cold start, all of them at
 * once, and the replacement token cannot be verified either because the key set is still down. So
 * the refusal stands, and it takes the generic retryable status with no challenge header.
 *
 * Refusing is the part that is not negotiable: an unverifiable token is never accepted. What moves
 * is only the status and the challenge.
 */
describe('a key set that could not be consulted', () => {
  /**
   * Replace the whole fixture rather than adding a route to it. The harness persists its JWKS
   * interceptor and undici answers from the first registered match, so a second route for the same
   * path would never be reached and every case here would quietly run against a healthy key set.
   */
  async function withJwks(
    jwks: JwksOutcome | 'healthy',
    serverOptions: TestServerOptions = {}
  ): Promise<TestServer> {
    await server.close();
    await upstream.restore();
    upstream = installUpstreamMock([trustedKey], jwks === 'healthy' ? {} : { jwks });
    server = await startTestServer(serverOptions);
    return server;
  }

  /**
   * Includes a healthy-credential 401 so an always-503 server fails.
   * 404 and 503 are one incident here: jose refuses anything that is not 200, with no status.
   */
  const KEY_SET_OUTCOMES: readonly {
    readonly label: string;
    readonly jwks: JwksOutcome | 'healthy';
    readonly about: 'key_set' | 'credential';
    readonly status: number;
    readonly token: () => Promise<string>;
    /** Overrides for the fixture, for the row that has to reach the request budget. */
    readonly serverOptions?: TestServerOptions;
  }[] = [
    {
      label: 'the endpoint answers 503',
      jwks: { status: 503, body: { error: 'service unavailable' } },
      about: 'key_set',
      status: 503,
      token: () => sentinelToken(),
    },
    {
      label: 'the endpoint answers 404, which this layer cannot tell from an outage',
      jwks: { status: 404, body: { error: 'not found' } },
      about: 'key_set',
      status: 503,
      token: () => sentinelToken(),
    },
    {
      label: 'the endpoint answers 200 with a body that is not a key set',
      jwks: { status: 200, body: { message: 'the authorization server is restarting' } },
      about: 'key_set',
      status: 503,
      token: () => sentinelToken(),
    },
    {
      label: 'the endpoint cannot be connected to at all',
      jwks: 'unreachable',
      about: 'key_set',
      status: 503,
      token: () => sentinelToken(),
    },
    {
      // Cheap now, and it was not before: the budget is this project's own and injectable, so this
      // row costs 300ms rather than the five-second wait the verification library's inherited
      // default demanded.
      label: 'the endpoint outlasts the whole request budget',
      jwks: { status: 200, body: { keys: [] }, delayMs: 2_000 },
      about: 'key_set',
      status: 503,
      token: () => sentinelToken(),
      serverOptions: { requestDeadlineMs: 300 },
    },
    {
      label: 'the endpoint is healthy and the credential is what failed',
      jwks: 'healthy',
      about: 'credential',
      status: 401,
      token: () => sentinelToken({ exp: '-5m' }),
    },
  ];

  it.each(KEY_SET_OUTCOMES)(
    'refuses the request when $label',
    async ({ label, jwks, about, status, token, serverOptions }) => {
      const running = await withJwks(jwks, serverOptions ?? {});

      const response = await listTools(running, await token());
      const reports = reportedCodes();

      expect(response.status, `${label}: the measured status`).toBe(status);
      // Counted, not merely present: a path that reported twice for one refusal would double every
      // rate an alert is calibrated against, and `toBeDefined` on the first entry cannot see it.
      expect(reports, `${label}: exactly one report for one refusal`).toHaveLength(1);
      const [code] = reports;

      if (about === 'key_set') {
        expectNotAnAuthChallenge(response, label);
        expect(
          code,
          `${label}: the code has to say the key set was the problem, or an operator pages the wrong team and the client-visible answer no longer carries the distinction`
        ).toMatch(/^upstream_failure\.key_set_/);
      } else {
        expectUnauthorizedChallenge(response, label);
        expect(
          code,
          `${label}: a credential failure is reported as one, never as a key-set outage — otherwise "retry later" is the answer to a token that will never verify`
        ).not.toMatch(/^upstream_failure\./);
      }
    }
  );

  /**
   * Reachable-but-unusable and unreachable are different incidents — a bad answer from a live
   * endpoint against no endpoint at all — so an operator reading "the key set is down" needs to know
   * which. That is the whole claim here: the two causes are not collapsed into one code. It is what
   * the rows above cannot see, since each of them compares only against the credential counterpart.
   *
   * **What this does NOT establish, and no assertion in this file does: which arm is reached by
   * positive evidence.** That property lives one layer down and is structural rather than asserted.
   * The key-set arm is reachable only through the purpose-built error the validator raises at the
   * key-retrieval call, so the arm is decided by *where* the failure happened, not by testing a cause
   * against a third-party class hierarchy — and a new error class appearing inside the JOSE library
   * cannot silently move a request from one arm to the other.
   *
   * The single fall-through sits on the **credential** side by decision, with a code no decided arm
   * uses. That direction is not arbitrary: a transport failure misread as a credential failure
   * answers 401 and produces a client refresh loop, which is visible and diagnosable, whereas a
   * credential failure misread as transport answers "retry later" forever for a token that will never
   * verify and files a security rejection as an outage.
   *
   * One nuance, because it is what this test actually turns on: a base-class test does still exist
   * inside the validator, and it chooses between the two key-set **labels** rather than between arms.
   * So a regression there mislabels an outage and misroutes a page — which is what this case catches —
   * while being unable to turn a refusal into "retry later".
   *
   * Neither spelling is pinned, only their distinctness. The `upstream_failure` class prefix the rows
   * assert is the specified one; everything after it is this server's own choice and nothing outside
   * this repository depends on it.
   */
  it('tells a key set that answered unusably apart from one that could not be reached', async () => {
    await withJwks({ status: 503, body: { error: 'service unavailable' } });
    await listTools(server, await sentinelToken());
    const [answered] = reportedCodes();

    await withJwks('unreachable');
    await listTools(server, await sentinelToken());
    const [unreachable] = reportedCodes();

    expect(answered, 'the answered-but-unusable case reported').toBeDefined();
    expect(unreachable, 'the unreachable case reported').toBeDefined();
    expect(
      unreachable,
      'both are key-set outages and both are retryable, but they are different incidents: one is a bad response from a live endpoint, the other is no endpoint at all'
    ).not.toBe(answered);
  });

  /**
   * The OTHER half of the requirement, and every case above is blind to it: a key set already held
   * and still inside its lifetime is served from, and only a request that cannot be answered from it
   * fails closed. Refusing first and asking later would turn one bad response from the authorization
   * server into a full outage — which is the failure mode the retryable class exists to avoid, not
   * one to introduce on the way to avoiding it.
   *
   * This case must NOT restart the server. Every row above builds a fresh validator, so its key set
   * is always cold, and an implementation that refused on any hiccup regardless of a usable cached
   * set would pass all four of them.
   *
   * The endpoint is swapped underneath a running server instead. No lifetime value is asserted:
   * how long a key may be reused is a configuration decision that has not been taken, and pinning a
   * number here would pre-empt it.
   */
  it('serves from a key set it already holds rather than refusing on a later outage', async () => {
    const jwksPath = new URL(MCP_JWKS_URL).pathname;
    const goodToken = (): Promise<string> =>
      makeToken({
        key: trustedKey,
        iss: MCP_EXPECTED_ISSUER,
        aud: MCP_RESOURCE_IDENTIFIER,
        scopes: ALL_SCOPES,
        sub: USER_A,
      });

    const first = await listTools(server, await goodToken());
    expect(first.rpc?.id, 'the first request warms the key set and is served').toBe(1);
    expect(
      upstream.callsTo(jwksPath).length,
      'and it really did fetch the key set, or there was never a cache to serve from and the second half of this test proves nothing'
    ).toBe(1);

    // The endpoint goes down under a server that is already holding the key set. Same server, same
    // validator: only the far end changes.
    await upstream.restore();
    upstream = installUpstreamMock([trustedKey], {
      jwks: { status: 503, body: { error: 'service unavailable' } },
    });

    const second = await listTools(server, await goodToken());

    expect(
      second.rpc?.id,
      'a key set already in hand is still good: the outage must not refuse a token this server can already verify'
    ).toBe(1);
    expect(
      second.status,
      'and specifically not the retryable class, which belongs to a key set that could not be consulted at all'
    ).not.toBe(503);
    expect(
      upstream.callsTo(jwksPath),
      'positively: the endpoint was never consulted for the second request, which is what "served from the key set it already holds" means'
    ).toEqual([]);
    expect(
      reportedCodes(),
      'and a served request is not an operator signal, so the outage behind it reports nothing either'
    ).toEqual([]);
  });

  /** The refusal itself, which is the half that does not move. */
  it('never serves the request when the key set is unavailable', async () => {
    const running = await withJwks('unreachable');

    const response = await listTools(running, await sentinelToken());

    expect(
      response.rpc?.id,
      'a served request echoes the JSON-RPC id. An unverifiable token is refused whatever the reason the key set could not be consulted — the retryable class changes the status, never the verdict'
    ).toBeUndefined();
  });

  /** `it.each([])` registers nothing and exits 0, so a table losing rows would go quiet. */
  it('keeps a floor under the key-set outcome table', () => {
    const keySetRows = KEY_SET_OUTCOMES.filter((row) => row.about === 'key_set');
    const credentialRows = KEY_SET_OUTCOMES.filter((row) => row.about === 'credential');

    expect(
      keySetRows.length,
      'the ways a key set fails to be consultable: a bad status, a status that merely looks like a deployment error, a body that is not a key set, no connection at all, and an endpoint that never finishes answering'
    ).toBeGreaterThanOrEqual(5);
    expect(
      credentialRows.length,
      'anti-vacuity: with no credential row, a server answering 503 with no challenge to every request passes this whole describe block'
    ).toBeGreaterThanOrEqual(1);
    expect(
      new Set(KEY_SET_OUTCOMES.map((row) => row.label)).size,
      'and every row is distinct, so the counts cannot be met by repeating one'
    ).toBe(KEY_SET_OUTCOMES.length);
  });
});

/**
 * A refusal renders two strings a reader trusts: the `WWW-Authenticate` parameter a client parses,
 * and the operator code that reaches the log. Both are single-line quoted contexts, so a value
 * carrying a quote or a line break in either one forges a second parameter or a second log entry.
 *
 * The scope name is the only value from outside this module that reaches either. Nothing constrains
 * it at runtime — it is meant to be one of this server's own frozen scope names, and "meant to" is
 * not a control.
 */
describe('a scope name that tries to forge a parameter or a log entry', () => {
  /** A value that would close the quoted `scope` parameter and open an `error` of its own, then
   *  start a fresh log line. Both halves are needed: the header sanitiser and the log sanitiser are
   *  the same function called from two places, so a value exercising only one leaves the other's
   *  call site free to be deleted. */
  const FORGED_SCOPE = `${SCOPES.meallogWrite}", error="none\nlevel=info msg="access granted"`;

  /** Quoted-string aware: a comma inside quotes is data, and a parser that split on every comma
   *  would report the forged parameter as a legitimate one. */
  function countChallengeParameters(challenge: string): number {
    const withoutScheme = challenge.replace(/^Bearer\s+/i, '');
    return (withoutScheme.match(/[a-z_]+=(?:"(?:[^"\\]|\\.)*"|[^,]*)/gi) ?? []).length;
  }

  /**
   * The control for the counter, and it is not optional: `toBe(3)` is satisfied just as well by a
   * parser that cannot see a fourth parameter at all. This pins both directions — a comma inside a
   * quoted value stays data, and a parameter that really was forged is counted.
   */
  it('counts a forged parameter when one is genuinely present', () => {
    const oneParameterCarryingACommaInItsValue =
      'Bearer error="insufficient_scope", scope="meallog:write, error=none", resource_metadata="https://x/y"';
    const fourWhereTheThirdWasForged =
      'Bearer error="insufficient_scope", scope="meallog:write", error="none", resource_metadata="https://x/y"';

    expect(
      countChallengeParameters(oneParameterCarryingACommaInItsValue),
      'a comma inside a quoted value is data, not a separator: a parser that split on every comma would call the sanitised form a forgery'
    ).toBe(3);
    expect(
      countChallengeParameters(fourWhereTheThirdWasForged),
      'and a parameter that escaped its quotes IS counted, so the assertion below is about the server rather than about the parser being blind'
    ).toBe(4);
  });

  it('renders neither the challenge nor the report as more than it is', async () => {
    await server.close();
    server = await startTestServer({ missingScopeFor: () => FORGED_SCOPE });

    const good = await makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: ALL_SCOPES,
      sub: USER_A,
    });
    const response = await listTools(server, good);

    expect(response.status, 'insufficient scope is 403 before dispatch').toBe(403);

    const challenge = response.challenge ?? '';
    expect(challenge, 'the challenge was emitted').not.toBe('');
    expect(
      countChallengeParameters(challenge),
      `the challenge carries exactly error, scope and resource_metadata. Got: ${challenge}`
    ).toBe(3);
    expect(
      challenge,
      'a quote inside a quoted parameter value closes it early, and everything after it is read by the client as parameters the server never sent'
    ).not.toContain('", error="none');

    const [code] = reportedCodes();
    expect(code, 'the denial was reported').toBeDefined();
    expect(
      code ?? '',
      'a newline in a log value forges a whole entry, and the reader that matters is the one that is hardest to protect'
    ).not.toMatch(/[\r\n]/);
    expect(
      code ?? '',
      'and a quote in it forges a field in the JSON record the composition root writes, so the report is sanitised at its own call site rather than relying on the header builder having been called first'
    ).not.toContain('"');
  });
});

describe('what a rejected credential must never leave behind', () => {
  /** Minted fresh per test, from the one table every case here iterates. */
  function rejectableTokens(): Promise<string[]> {
    return Promise.all(REJECTION_SHAPES.map((shape) => shape.make()));
  }

  /** The floor guards the table the assertions actually run over, which is the only kind of floor
   *  worth having: `it.each([])` registers nothing and a shrunken table quietens every count
   *  assertion that derives its expectation from the table's own length. */
  it('keeps a floor under the rejection-shape table', () => {
    expect(
      REJECTION_SHAPES.length,
      'anti-vacuity: proving absence on one rejection path and assuming it on the rest is how this leak survives'
    ).toBeGreaterThanOrEqual(6);
    expect(
      new Set(REJECTION_SHAPES.map((shape) => shape.label)).size,
      'and every shape is distinct, so the count cannot be met by repeating one'
    ).toBe(REJECTION_SHAPES.length);
  });

  it('puts no token claim value in anything the composition root logs', async () => {
    const tokens = await rejectableTokens();
    for (const token of tokens) {
      await listTools(server, token);
    }

    // The exact record shape the composition root writes. Asserted rather than assumed, because
    // the whole control is "log a code derived from the error's class, never the error".
    const lines = server.errors.map((error) =>
      JSON.stringify({ level: 'error', msg: error.message })
    );

    expect(
      lines.length,
      'anti-vacuity: "no sentinel appears in the logs" is trivially true over an empty log. Every token above must have produced a report'
    ).toBe(tokens.length);

    for (const line of lines) {
      for (const sentinel of SENTINEL_VALUES) {
        expect(
          line,
          `a request that failed authentication must not log ${sentinel}. jose attaches the decoded payload to the error and to its cause, so this leaks the moment anything reports the object instead of a code`
        ).not.toContain(sentinel);
      }
    }
  });

  /**
   * The same absence over the whole reachable graph of every reported error, not just the message.
   * The composition root logs `error.message` today; this is what stops the leak the day someone
   * logs the error, which is the natural next change and the one that would reintroduce it
   * silently — including the wrapped form, `new Error(code, { cause })`, where the payload rides in
   * one level down.
   */
  it('attaches no decoded payload to the reported error, at any depth', async () => {
    for (const token of await rejectableTokens()) {
      await listTools(server, token);
    }

    expect(
      server.errors.length,
      'anti-vacuity: every rejection shape must have produced a report before absence over them means anything'
    ).toBe(REJECTION_SHAPES.length);

    /**
     * SCOPED TO THE VALIDATION PATH, and that is a limit rather than an oversight.
     *
     * Three other things report through `onError`: the authorization fault path and the two SDK
     * paths. None of them is asserted here, because on those paths the transport hands the caught
     * object straight to the reporter, so what the report carries is whatever the collaborator threw
     * — a property of the fixture, not of this server. An "absence of sentinels" assertion over an
     * error this file constructed would certify the fixture and read as if it certified the server,
     * which is the exact shape of the defect this file was rewritten to remove.
     *
     * It is also unfalsifiable rather than merely weak: the decoded claims are local to the
     * authorization step and are not in scope where the fault is caught, so there is no version of
     * the transport that could attach them there for an assertion to catch. Covering those producers
     * needs the reporting boundary changed, which is not this file's to do.
     */
    for (const error of server.errors) {
      const everything = renderWholeError(error);

      for (const sentinel of SENTINEL_VALUES) {
        expect(
          everything,
          `nothing reachable from a reported error may carry ${sentinel} — not the message, the stack, a payload hung on it, or a payload hung on its cause`
        ).not.toContain(sentinel);
      }

      expect(
        Object.getOwnPropertyNames(error),
        'and no payload property at the top level either, which is what makes the absence above structural rather than incidental'
      ).not.toContain('payload');
    }
  });

  /**
   * The control for the assertion above, and it is not optional: the renderer it uses replaced one
   * that returned `false` for BOTH leak shapes, so the test was green over a payload that was
   * present. This pins the renderer's reach in the two shapes that matter — a payload on the error
   * and a payload on its cause — so the absence result above means "not there" rather than
   * "not looked for".
   */
  it('finds a payload the renderer must be able to reach', () => {
    const joseLike = Object.assign(new Error('exp claim timestamp check failed'), {
      payload: { sub: SENTINELS.sub, scope: SENTINELS.scope },
    });

    expect(
      renderWholeError(joseLike),
      'control: a payload hung directly on the error is visible to the renderer'
    ).toContain(SENTINELS.sub);

    expect(
      renderWholeError(new Error('unauthorized.expired', { cause: joseLike })),
      'control: and so is one hung on the cause, which is the shape a wrapped rethrow produces and the one the previous renderer could not see'
    ).toContain(SENTINELS.sub);

    expect(
      renderWholeError(new Error('unauthorized.expired')),
      'and the renderer does not invent it: a bare error carrying no payload renders without the sentinel, so the two assertions above are not passing on the message'
    ).not.toContain(SENTINELS.sub);
  });

  it('puts no token claim value on the wire either', async () => {
    for (const token of await rejectableTokens()) {
      const response = await listTools(server, token);
      const onTheWire = `${response.rawBody}\n${response.challenge ?? ''}`;

      for (const sentinel of SENTINEL_VALUES) {
        expect(
          onTheWire,
          `the 401 response must not echo ${sentinel} back: a challenge is read by whoever sent the request, which is not established to be whoever the token names`
        ).not.toContain(sentinel);
      }
    }
  });

  /**
   * The sentinels have to be findable when they ARE present, or every absence assertion above is
   * passing because the needle was never in the haystack.
   */
  it('finds a sentinel in a string that genuinely contains one', async () => {
    const token = await sentinelToken({ exp: '-5m' });

    expect(
      token.length,
      'the sentinel identity really is inside the token that was presented, so the absence assertions above are about redaction rather than about a claim that was never set'
    ).toBeGreaterThan(0);

    const decodedPayload = Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8');
    for (const sentinel of SENTINEL_VALUES) {
      expect(
        decodedPayload,
        `control: ${sentinel} is present in the presented token, so its absence from the logs is a property of the server rather than of the fixture`
      ).toContain(sentinel);
    }
  });
});
