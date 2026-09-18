/**
 * Live grant introspection (RFC 7662). Transport under `client.ts` is mocked; the client is not.
 * Counted properties: no positive cache; only `active: false` is unauthorized; negative cache
 * may only refuse faster, never permit.
 */

import { createSecretKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { jwtVerify } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { McpError, type McpErrorClass } from '../../../src/errors.ts';
import {
  createRevocationChecker,
  type OperationalEvent,
  type RevocationChecker,
  type SecurityEvent,
} from '../../../src/auth/revocation.ts';
import { CLIENT_ASSERTION_TYPE } from '../../../src/auth/upstreamToken.ts';
import { CORRELATION_ID_HEADER } from '../../../src/upstream/client.ts';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../../scripts/makeToken.ts';
import {
  installUpstreamMock,
  type UpstreamMock,
  type WireCall,
} from '../../support/upstreamMock.ts';
import {
  ALL_SCOPES,
  AUTH_SERVER_ORIGIN,
  CLIENT_ID,
  GRANT_A,
  INTROSPECTION_PATH,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  RESOURCE_METADATA_URL,
  SCOPES,
  USER_A,
} from '../../support/testEnv.ts';

const INTROSPECTION_URL = `${AUTH_SERVER_ORIGIN}${INTROSPECTION_PATH}`;
const CORRELATION_ID = 'correlation-under-test';
const DEADLINE_MS = 5_000;

/** An arbitrary fixed instant. Every clock in this suite is injected, so nothing waits. */
const START_MS = 1_800_000_000_000;

/** In a 200 body and in an error body, so "no body reaches the payload" is checkable. */
const RESPONSE_BODY_MARKER = 'UPSTREAM-BODY-MARKER-d15ea5e';

/** What the authorization server returns when the grant is live. These fields exist only then. */
const ACTIVE_PAYLOAD = {
  active: true,
  scope: ALL_SCOPES.join(' '),
  sub: USER_A,
  client_id: CLIENT_ID,
  grant_id: GRANT_A,
  aud: MCP_RESOURCE_IDENTIFIER,
  iss: MCP_EXPECTED_ISSUER,
} as const;

let signingKey: TestKeyPair;
let assertionKey: { readonly privateKey: KeyObject; readonly publicKey: KeyObject };
let accessToken: string;
let secondAccessToken: string;
/** Distinct values for the cache sweep. Signed for real like every other token here. */
let cacheTokens: string[];
let upstream: UpstreamMock;
let clockMs: number;

interface Harness {
  readonly checker: RevocationChecker;
  readonly operational: OperationalEvent[];
  readonly security: SecurityEvent[];
}

interface CheckerOverrides {
  /** Blank is how an identifier nobody supplied arrives, and it is refused rather than derived. */
  readonly clientId?: string;
  /** A key the assertion cannot be signed with is a configuration fault, not a network one. */
  readonly clientAssertionKey?: KeyObject;
  /** The token travels in this request's body, so the scheme is a credential-exposure decision. */
  readonly introspectionUrl?: string;
}

function makeChecker(negativeCacheMaxAgeMs = 0, overrides: CheckerOverrides = {}): Harness {
  const operational: OperationalEvent[] = [];
  const security: SecurityEvent[] = [];

  const checker = createRevocationChecker({
    introspectionUrl: overrides.introspectionUrl ?? INTROSPECTION_URL,
    clientId: overrides.clientId ?? CLIENT_ID,
    clientAssertionKey: overrides.clientAssertionKey ?? assertionKey.privateKey,
    resourceMetadataUrl: RESOURCE_METADATA_URL,
    negativeCacheMaxAgeMs,
    now: () => clockMs,
    logOperational: (event) => operational.push(event),
    logSecurity: (event) => security.push(event),
  });

  return { checker, operational, security };
}

function check(
  checker: RevocationChecker,
  token = accessToken,
  deadlineMs = DEADLINE_MS
): Promise<unknown> {
  return checker.assertGrantActive({
    token,
    correlationId: CORRELATION_ID,
    deadlineMs,
  });
}

/** Rejects with an `McpError` of exactly this class. "Did not throw unauthorized" is not enough. */
async function expectRejectedClass(
  promise: Promise<unknown>,
  expected: McpErrorClass,
  context: string
): Promise<McpError> {
  let caught: unknown;
  await promise.then(
    () => undefined,
    (error: unknown) => {
      caught = error;
    }
  );

  expect(
    caught,
    `${context}: must reject. A resolved introspection here is a grant permitted without an answer.`
  ).toBeInstanceOf(McpError);
  if (!(caught instanceof McpError))
    throw new Error('unreachable: the assertion above fails first');

  expect(caught.class, `${context}: expected the ${expected} class`).toBe(expected);
  return caught;
}

function introspectionCalls(): readonly WireCall[] {
  return upstream.callsTo(INTROSPECTION_PATH);
}

function formOf(call: WireCall): URLSearchParams {
  return new URLSearchParams(call.body);
}

function headersOf(call: WireCall): Map<string, string> {
  return new Map(
    Object.entries(call.headers).map(([name, value]) => [
      name.toLowerCase(),
      Array.isArray(value) ? value.join(', ') : value,
    ])
  );
}

beforeAll(async () => {
  signingKey = await createTestKeyPair('mcp-signing-key-1');
  assertionKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });

  accessToken = await makeToken({
    key: signingKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_A,
    grantId: GRANT_A,
    clientId: CLIENT_ID,
    jti: 'jti-under-test',
  });

  cacheTokens = await Promise.all(
    ['sweep-a', 'sweep-b', 'sweep-c'].map(async (jti) =>
      makeToken({
        key: signingKey,
        iss: MCP_EXPECTED_ISSUER,
        aud: MCP_RESOURCE_IDENTIFIER,
        scopes: ALL_SCOPES,
        sub: USER_A,
        grantId: `${GRANT_A}-${jti}`,
        clientId: CLIENT_ID,
        jti,
      })
    )
  );

  secondAccessToken = await makeToken({
    key: signingKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_A,
    grantId: `${GRANT_A}-second`,
    clientId: CLIENT_ID,
    jti: 'jti-under-test-2',
  });
});

beforeEach(() => {
  clockMs = START_MS;
  upstream = installUpstreamMock([signingKey]);
});

afterEach(async () => {
  await upstream.restore();
});

describe('a live grant', () => {
  it('resolves the fields the authorization server returns only when active', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker, operational, security } = makeChecker();

    await expect(check(checker)).resolves.toEqual({
      grantId: GRANT_A,
      scopes: [SCOPES.nutritionRead, SCOPES.mealplanRead, SCOPES.meallogWrite],
      subject: USER_A,
      clientId: CLIENT_ID,
    });

    expect(operational, 'a successful check is not an operational event').toHaveLength(0);
    expect(security, 'a successful check is not a security event').toHaveLength(0);
  });

  it('treats an absent scope as no scopes, never as all of them', async () => {
    upstream.introspect({ active: true, sub: USER_A, client_id: CLIENT_ID, grant_id: GRANT_A });
    const { checker } = makeChecker();

    await expect(check(checker)).resolves.toEqual({
      grantId: GRANT_A,
      scopes: [],
      subject: USER_A,
      clientId: CLIENT_ID,
    });
  });
});

describe('a positive result is never cached', () => {
  it('makes TWO introspection requests for two successful checks', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker();

    await expect(check(checker)).resolves.toBeDefined();
    await expect(check(checker)).resolves.toBeDefined();

    expect(
      introspectionCalls().length,
      'a cached "active" is exactly what lets a revoked grant keep working: every request asks'
    ).toBe(2);
  });

  it('still asks every time when a negative cache is configured', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker(60_000);

    await expect(check(checker)).resolves.toBeDefined();
    await expect(check(checker)).resolves.toBeDefined();
    await expect(check(checker)).resolves.toBeDefined();

    expect(
      introspectionCalls().length,
      'the negative cache must have no positive counterpart, whatever its TTL'
    ).toBe(3);
  });

  it('asks again after a live grant answers, even with the clock frozen', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker(60_000);

    await expect(check(checker)).resolves.toBeDefined();
    const afterFirst = introspectionCalls().length;
    await expect(check(checker)).resolves.toBeDefined();

    expect(
      introspectionCalls().length - afterFirst,
      'a frozen clock must not make a positive answer reusable'
    ).toBe(1);
  });
});

describe('active:false is the only outcome that means unauthorized', () => {
  it('throws the unauthorized class carrying the resource-metadata pointer', async () => {
    upstream.introspect({ active: false });
    const { checker } = makeChecker();

    const error = await expectRejectedClass(
      check(checker),
      'unauthorized',
      'an authenticated explicit negative'
    );

    const model = error.toModel();
    expect(model.class).toBe('unauthorized');
    expect(
      model,
      'the 401 must carry resource_metadata, or the client cannot find the authorization server'
    ).toMatchObject({ resourceMetadataUrl: RESOURCE_METADATA_URL });

    const log = error.toLog();
    expect(log.class).toBe('unauthorized');
    expect(
      log,
      'the log side is a different payload, not the model payload serialised twice'
    ).not.toEqual(model);
  });

  it('does not reach the grant fields of an inactive answer', async () => {
    // An inactive body carrying grant fields is a contract violation; reading them anyway would
    // be a grant assembled from a refusal.
    upstream.introspect({ active: false, scope: ALL_SCOPES.join(' '), grant_id: GRANT_A });
    const { checker } = makeChecker();

    await expectRejectedClass(check(checker), 'unauthorized', 'inactive with fields present');
  });
});

describe('an answer that could not be established is an outage, not a decision', () => {
  interface Outage {
    readonly label: string;
    readonly arrange: () => void;
    readonly statusClass: string;
    /**
     * Pinned per row, not just the class. The three request-failure arms below are
     * indistinguishable by class alone, and it was exactly that gap — a live outage and a spent
     * deadline reported under each other's code — that a class-only table could not see.
     */
    readonly errorCode: string;
    /** Overrides the usable slice, for the arm that is about the slice being unusable. */
    readonly deadlineMs?: number;
  }

  const outages: readonly Outage[] = [
    {
      label: 'the endpoint answers 500',
      arrange: () => {
        upstream.introspect({ error: RESPONSE_BODY_MARKER }, 500);
      },
      statusClass: '5xx',
      errorCode: 'introspection_status',
    },
    {
      label: 'the endpoint answers 400',
      arrange: () => {
        upstream.introspect({ error: RESPONSE_BODY_MARKER }, 400);
      },
      statusClass: '4xx',
      errorCode: 'introspection_status',
    },
    {
      label: 'the body is not JSON',
      arrange: () => {
        upstream.route({
          origin: AUTH_SERVER_ORIGIN,
          path: INTROSPECTION_PATH,
          method: 'POST',
          status: 200,
          body: `<html>${RESPONSE_BODY_MARKER}</html>`,
        });
      },
      statusClass: '2xx',
      errorCode: 'introspection_malformed',
    },
    {
      label: 'the body carries no active field',
      arrange: () => {
        upstream.introspect({ scope: ALL_SCOPES.join(' '), sub: USER_A });
      },
      statusClass: '2xx',
      errorCode: 'introspection_malformed',
    },
    {
      label: 'active is the STRING "false"',
      arrange: () => {
        upstream.introspect({ active: 'false', sub: USER_A });
      },
      statusClass: '2xx',
      errorCode: 'introspection_malformed',
    },
    {
      label: 'active is the STRING "true"',
      arrange: () => {
        upstream.introspect({ active: 'true', sub: USER_A, grant_id: GRANT_A });
      },
      statusClass: '2xx',
      errorCode: 'introspection_malformed',
    },
    {
      label: 'active is the number 1',
      arrange: () => {
        upstream.introspect({ active: 1, sub: USER_A, grant_id: GRANT_A });
      },
      statusClass: '2xx',
      errorCode: 'introspection_malformed',
    },
    {
      label: 'the body is a JSON array',
      arrange: () => {
        upstream.route({
          origin: AUTH_SERVER_ORIGIN,
          path: INTROSPECTION_PATH,
          method: 'POST',
          status: 200,
          body: '[{"active":true}]',
        });
      },
      statusClass: '2xx',
      errorCode: 'introspection_malformed',
    },
    // The three request-failure arms, adjacent on purpose. They are what the single
    // `instanceof TypeError` discriminator conflated, and reading them together is the only way a
    // future reader sees that the obvious test puts a live outage and a spent budget on one arm.
    {
      label: 'the endpoint cannot be reached',
      // No intercept at all: disableNetConnect refuses it before it leaves, which is the shape a
      // refused connection or a DNS failure arrives in. Measured: fetch reports this as a
      // TypeError CARRYING a cause, which is what separates it from our own guard.
      arrange: () => undefined,
      statusClass: 'unreachable',
      errorCode: 'introspection_unreachable',
    },
    {
      label: 'the slice runs out before the issuer answers',
      arrange: () => {
        upstream.route({
          origin: AUTH_SERVER_ORIGIN,
          path: INTROSPECTION_PATH,
          method: 'POST',
          status: 200,
          body: { ...ACTIVE_PAYLOAD },
          delayMs: 400,
        });
      },
      // A real abort, not a simulated one: the reply is held past the slice, so the signal fires
      // and fetch rejects with a TimeoutError. Nothing here waits on a real clock beyond 10ms.
      deadlineMs: 10,
      statusClass: 'timeout',
      errorCode: 'introspection_timeout',
    },
    {
      label: 'the slice is unusable, so the request is never built',
      arrange: () => {
        upstream.introspect({ ...ACTIVE_PAYLOAD });
      },
      deadlineMs: 0,
      statusClass: 'unusable_request',
      errorCode: 'introspection_request_unbuildable',
    },
  ];

  it('has more than one outage shape, and the table is not empty', () => {
    expect(
      outages.length,
      'emptying this table would delete every negative case in silence'
    ).toBeGreaterThanOrEqual(11);
  });

  it.each(outages)('$label fails as upstream_failure, never as unauthorized', async (outage) => {
    outage.arrange();
    const { checker, operational, security } = makeChecker();

    const error = await expectRejectedClass(
      check(checker, accessToken, outage.deadlineMs ?? DEADLINE_MS),
      'upstream_failure',
      `${outage.label}: presenting this as 401 sends every client into refresh-and-retry over an outage`
    );

    expect(
      error.class,
      `${outage.label}: an unestablished answer must never be reported as an expired credential`
    ).not.toBe('unauthorized');

    const log = error.toLog();
    expect(
      log,
      `${outage.label}: the log side records a status class, never a status code`
    ).toMatchObject({
      class: 'upstream_failure',
      statusClass: outage.statusClass,
      errorCode: outage.errorCode,
      endpointClass: 'authorization_server_introspection',
      correlationId: CORRELATION_ID,
    });
    expect(
      Object.keys(log).sort(),
      `${outage.label}: the log payload carries exactly the declared fields`
    ).toEqual(['class', 'correlationId', 'endpointClass', 'errorCode', 'latencyMs', 'statusClass']);
    expect(
      operational,
      `${outage.label}: an outage is operational, and an operator needs the code to tell these apart`
    ).toHaveLength(1);
    expect(operational[0]).toMatchObject({
      event: 'introspection_failed',
      errorCode: outage.errorCode,
      statusClass: outage.statusClass,
    });
    expect(
      security,
      `${outage.label}: no grant decision was reached, so nothing was denied`
    ).toHaveLength(0);
  });

  it('keeps the response body and the status code out of both payloads', async () => {
    upstream.introspect({ error: RESPONSE_BODY_MARKER, hint: RESPONSE_BODY_MARKER }, 500);
    const { checker } = makeChecker();

    const error = await expectRejectedClass(
      check(checker),
      'upstream_failure',
      'a 500 with a body'
    );

    const model = JSON.stringify(error.toModel());
    const log = JSON.stringify(error.toLog());

    expect(model, 'the model gets a generic retryable message').not.toContain(RESPONSE_BODY_MARKER);
    expect(
      log,
      'the log gets a status class, an error code and a latency — never the body'
    ).not.toContain(RESPONSE_BODY_MARKER);
    expect(model, 'no status code reaches the model').not.toContain('500');
    expect(log, 'the log records the family, not the code').not.toContain('500');
    expect(error.toModel()).toMatchObject({ retryable: true });
  });

  it('records the transport failure before the grant fields are read', async () => {
    upstream.introspect({ active: true, grant_id: GRANT_A }, 503);
    const { checker } = makeChecker();

    // An `active: true` under a 5xx is the shape that most tempts a status-blind reader.
    await expectRejectedClass(
      check(checker),
      'upstream_failure',
      'active:true under a 5xx is still an outage'
    );
  });
});

describe('the two log channels', () => {
  it('logs a transport failure as operational and NOT as a security event', async () => {
    upstream.introspect({ error: 'boom' }, 500);
    const { checker, operational, security } = makeChecker();

    await expectRejectedClass(check(checker), 'upstream_failure', 'a 500');

    expect(operational, 'a key-set or introspection outage is operational').toHaveLength(1);
    expect(operational[0]).toMatchObject({
      event: 'introspection_failed',
      statusClass: '5xx',
      correlationId: CORRELATION_ID,
    });
    expect(
      security,
      'an outage is not a security anomaly: recording it as one buries the real ones'
    ).toHaveLength(0);
  });

  it('logs an inactive grant as a security event and NOT as an operational one', async () => {
    upstream.introspect({ active: false });
    const { checker, operational, security } = makeChecker();

    await expectRejectedClass(check(checker), 'unauthorized', 'active:false');

    expect(security, 'a denied dispatch is security-relevant').toHaveLength(1);
    expect(security[0]).toMatchObject({
      event: 'grant_inactive',
      correlationId: CORRELATION_ID,
      fromNegativeCache: false,
    });
    expect(
      operational,
      'a working endpoint giving a correct negative answer is not an operational failure'
    ).toHaveLength(0);
  });
});

describe('the negative cache refuses faster and never permits', () => {
  it('refuses a repeat WITHOUT a wire call, then asks again once the TTL passes', async () => {
    upstream.introspect({ active: false });
    const { checker, security } = makeChecker(60_000);

    await expectRejectedClass(check(checker), 'unauthorized', 'first refusal');
    expect(introspectionCalls().length, 'the first answer comes from the wire').toBe(1);

    clockMs = START_MS + 59_000;
    const cached = await expectRejectedClass(
      check(checker),
      'unauthorized',
      'a cached negative still refuses'
    );
    expect(
      introspectionCalls().length,
      'inside the TTL the refusal is served from the cache, so nothing is sent'
    ).toBe(1);
    expect(cached.toModel()).toMatchObject({ resourceMetadataUrl: RESOURCE_METADATA_URL });
    expect(security.at(-1), 'a cached refusal is recorded as one').toMatchObject({
      event: 'grant_inactive',
      fromNegativeCache: true,
    });

    clockMs = START_MS + 60_001;
    await expectRejectedClass(check(checker), 'unauthorized', 'after the TTL');
    expect(
      introspectionCalls().length,
      'past the TTL the entry is stale and the issuer is asked again'
    ).toBe(2);
  });

  it('never resolves from the cache, even when the grant came back', async () => {
    upstream.introspect({ active: false });
    const { checker } = makeChecker(60_000);

    await expectRejectedClass(check(checker), 'unauthorized', 'first refusal');

    // There is deliberately no path where a cache hit resolves: the cache can only refuse.
    for (const offsetMs of [0, 1_000, 30_000, 59_999]) {
      clockMs = START_MS + offsetMs;
      await expect(
        check(checker),
        `a cache hit at +${String(offsetMs)}ms must refuse, never permit dispatch`
      ).rejects.toBeInstanceOf(McpError);
    }

    expect(introspectionCalls().length, 'and none of those reached the wire').toBe(1);
  });

  it('caches nothing at a TTL of zero', async () => {
    upstream.introspect({ active: false });
    const { checker, security } = makeChecker(0);

    for (const attempt of [1, 2, 3]) {
      await expectRejectedClass(check(checker), 'unauthorized', `attempt ${String(attempt)}`);
    }

    expect(introspectionCalls().length, 'zero means ask every time').toBe(3);
    expect(
      security.every((event) => !event.fromNegativeCache),
      'no refusal may claim a cache that is disabled'
    ).toBe(true);
  });

  it('does not refuse a different token from another token cache entry', async () => {
    upstream.introspect({ active: false });
    const { checker } = makeChecker(60_000);

    await expectRejectedClass(check(checker, accessToken), 'unauthorized', 'first token');
    await expectRejectedClass(
      check(checker, secondAccessToken),
      'unauthorized',
      'a second token is a separate question'
    );

    expect(
      introspectionCalls().length,
      'the cache is keyed by token: a second grant must be asked about on its own'
    ).toBe(2);
  });

  it('does not carry a negative answer between checkers', async () => {
    upstream.introspect({ active: false });
    const first = makeChecker(60_000);
    await expectRejectedClass(check(first.checker), 'unauthorized', 'first checker');

    const second = makeChecker(60_000);
    await expectRejectedClass(check(second.checker), 'unauthorized', 'second checker');

    expect(introspectionCalls().length, 'each checker holds its own bounded cache').toBe(2);
  });
});

/**
 * The credential this server presents is its own, so failing to build it is a configuration
 * fault rather than a decision about the grant. It fails closed like everything else here, but it
 * fails as the retryable class with its own code — a raw TypeError or DOMException escaping the
 * authorization path is one the transport's class mapping does not recognise.
 *
 * v8 does not count a try/catch as a branch, so a full branch figure says nothing about this
 * path. It is pinned rather than trusted.
 */
describe('an unbuildable client assertion', () => {
  const unbuildable: readonly (readonly [string, CheckerOverrides])[] = [
    ['the client identifier is empty', { clientId: '' }],
    ['the client identifier is whitespace', { clientId: '   ' }],
    [
      'the key cannot sign',
      { clientAssertionKey: createSecretKey(Buffer.from('s'.repeat(32), 'utf8')) },
    ],
  ];

  it.each(unbuildable)(
    '%s: fails as upstream_failure, never as unauthorized',
    async (_label, overrides) => {
      upstream.introspect({ ...ACTIVE_PAYLOAD });
      const { checker } = makeChecker(0, overrides);

      const error = await expectRejectedClass(
        check(checker),
        'upstream_failure',
        'our own credential failing is not a statement about the grant'
      );

      expect(
        error.class,
        'reporting this as 401 would send the client to refresh a token that was never the problem'
      ).not.toBe('unauthorized');
      expect(error.toLog()).toMatchObject({
        class: 'upstream_failure',
        errorCode: 'introspection_assertion_unbuildable',
        statusClass: 'unusable_credential',
        correlationId: CORRELATION_ID,
      });
      expect(error.toModel(), 'the model gets the generic retryable message').toMatchObject({
        class: 'upstream_failure',
        retryable: true,
      });
    }
  );

  it.each(unbuildable)('%s: sends nothing at all', async (_label, overrides) => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const before = upstream.wireCalls().length;

    const { checker } = makeChecker(0, overrides);
    await expect(check(checker)).rejects.toBeInstanceOf(McpError);

    expect(
      upstream.wireCalls().length,
      'the assertion is built before the POST, so an unbuildable one reaches no endpoint'
    ).toBe(before);
    expect(introspectionCalls(), 'and the token value is never presented anywhere').toHaveLength(0);

    // Non-vacuity: the same route, reached by a checker whose credential CAN be built. Without
    // this, "nothing reached the wire" would also pass against a mock nobody registered.
    const working = makeChecker();
    await expect(check(working.checker)).resolves.toBeDefined();
    expect(introspectionCalls().length).toBe(1);
  });

  it.each(unbuildable)('%s: is operational, not a security event', async (_label, overrides) => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker, operational, security } = makeChecker(0, overrides);

    await expect(check(checker)).rejects.toBeInstanceOf(McpError);

    expect(operational, 'an operator needs to know their own credential is unusable').toHaveLength(
      1
    );
    expect(operational[0]).toMatchObject({
      event: 'introspection_failed',
      errorCode: 'introspection_assertion_unbuildable',
      statusClass: 'unusable_credential',
    });
    expect(
      security,
      'no grant was denied here: recording this as a security event would blame the user for our configuration'
    ).toHaveLength(0);
  });

  it('has more than one unbuildable shape, and the table is not empty', () => {
    expect(
      unbuildable.length,
      'emptying this table would delete every assertion-failure case in silence'
    ).toBeGreaterThanOrEqual(3);
  });
});

/**
 * The deadline is a slice of the one end-to-end budget, and it is required rather than optional:
 * an absent signal is not a generous timeout, it is no timeout, and this is the stage every later
 * one queues behind. An unusable slice is refused by the egress door before anything is sent.
 */
describe('an unusable deadline slice', () => {
  const unusable = [0, -1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY];

  it.each(unusable)(
    '%p is refused as upstream_failure, never as unauthorized',
    async (deadlineMs) => {
      upstream.introspect({ ...ACTIVE_PAYLOAD });
      const { checker, operational, security } = makeChecker();

      const error = await expectRejectedClass(
        check(checker, accessToken, deadlineMs),
        'upstream_failure',
        'a spent budget is a failure to ask, not an answer about the grant'
      );

      expect(error.class).not.toBe('unauthorized');
      expect(
        error.toLog(),
        'a refusal before sending never clears on retry, and is coded apart from the network'
      ).toMatchObject({
        class: 'upstream_failure',
        errorCode: 'introspection_request_unbuildable',
        statusClass: 'unusable_request',
        correlationId: CORRELATION_ID,
      });
      expect(operational, 'the operator is told their own request could not be built').toHaveLength(
        1
      );
      expect(security, 'no grant was denied').toHaveLength(0);
    }
  );

  it.each(unusable)('%p reaches no endpoint at all', async (deadlineMs) => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const before = upstream.wireCalls().length;

    const { checker } = makeChecker();
    await expect(check(checker, accessToken, deadlineMs)).rejects.toBeInstanceOf(McpError);

    expect(
      upstream.wireCalls().length,
      'the token value must not be presented on a request that cannot be bounded'
    ).toBe(before);

    // Non-vacuity: the same route, reached with a usable slice.
    await expect(check(checker)).resolves.toBeDefined();
    expect(introspectionCalls().length).toBe(1);
  });

  it('has more than one unusable shape, and the table is not empty', () => {
    expect(unusable.length).toBeGreaterThanOrEqual(5);
  });
});

/**
 * The scheme of the introspection endpoint is a credential-exposure decision, not a preference:
 * the inbound access token travels in this request's body. There is no configuration variable for
 * this URL, so the parameter is the only place the guarantee can live.
 */
describe('the introspection URL', () => {
  it.each([
    'http://auth.nutrihelp.test/api/oauth/introspect',
    'http://localhost:3000/api/oauth/introspect',
  ])('refuses the cleartext scheme %s at construction', (introspectionUrl) => {
    const before = upstream.wireCalls().length;

    expect(
      () => makeChecker(0, { introspectionUrl }),
      'a checker that exists can be called, so this must fail before it is built'
    ).toThrow(TypeError);

    expect(upstream.wireCalls().length, 'and nothing is sent while it fails').toBe(before);
  });

  it.each(['', '   ', 'not a url', '/api/oauth/introspect'])(
    'refuses a value that is not a URL (%j)',
    (introspectionUrl) => {
      const before = upstream.wireCalls().length;

      expect(() => makeChecker(0, { introspectionUrl })).toThrow(TypeError);
      expect(upstream.wireCalls().length).toBe(before);
    }
  );

  it('constructs on https and asks that endpoint', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker(0, { introspectionUrl: INTROSPECTION_URL });

    await expect(check(checker)).resolves.toBeDefined();
    expect(introspectionCalls().length, 'the guard must refuse a scheme, not every URL').toBe(1);
  });
});

/**
 * Identity on an active answer.
 *
 * The contract says the authorization server returns `sub`, `client_id` and the `grant_id`
 * extension ONLY when the grant is active. It does not say what a missing or wrong-typed one
 * means, and this module takes the strict reading: the answer was not established, exactly like a
 * non-boolean `active`. That is stricter than the contract requires and it is the safe direction —
 * downstream these become an audit envelope and a scope-denial record, where a coerced empty
 * string could not be told apart from a user who is the empty string.
 */
describe('an active answer must carry its identity', () => {
  const BROKEN: readonly (readonly [string, unknown])[] = [
    ['missing', undefined],
    ['a number', 12_345],
    ['null', null],
    ['an empty string', ''],
    ['an object', { nested: true }],
  ];

  const rows = ['sub', 'client_id', 'grant_id'].flatMap((field) =>
    BROKEN.map(([shape, value]) => ({ field, shape, value }))
  );

  it('covers every identity field against every broken shape', () => {
    expect(
      rows,
      'emptying this table would delete the whole identity guard in silence'
    ).toHaveLength(15);
  });

  it.each(rows)(
    'active:true with $field $shape is upstream_failure, never a grant',
    async ({ field, value }) => {
      // Rebuilt without the field rather than deleted from a copy: `missing` and `present but
      // broken` are one row shape, and a dynamic delete is banned here anyway.
      const payload: Record<string, unknown> = Object.fromEntries(
        Object.entries(ACTIVE_PAYLOAD).filter(([key]) => key !== field)
      );
      if (value !== undefined) payload[field] = value;

      upstream.introspect(payload);
      const { checker, operational, security } = makeChecker();

      const error = await expectRejectedClass(
        check(checker),
        'upstream_failure',
        `${field}: an answer missing its identity was not established`
      );

      expect(
        error.class,
        'this is a contract violation by the issuer, not a statement that the grant is gone'
      ).not.toBe('unauthorized');
      expect(error.toLog()).toMatchObject({
        class: 'upstream_failure',
        statusClass: 'incomplete_identity',
        correlationId: CORRELATION_ID,
      });
      expect(operational).toHaveLength(1);
      expect(security, 'no grant decision was reached, so nothing is denied').toHaveLength(0);
    }
  );

  it('still resolves when all three are present — the guard refuses shapes, not answers', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker();

    await expect(check(checker)).resolves.toEqual({
      grantId: GRANT_A,
      scopes: [SCOPES.nutritionRead, SCOPES.mealplanRead, SCOPES.meallogWrite],
      subject: USER_A,
      clientId: CLIENT_ID,
    });
  });
});

/**
 * The negative cache sweeps expired entries when it writes. That is a memory property and is not
 * observable from here on its own — the read path drops a stale entry too, so behaviour is
 * identical either way. What IS observable, and what a sweep can get wrong, is which entries
 * survive it: dropping a live denial would let a revoked grant back in for the rest of its window.
 */
describe('the negative cache sweep', () => {
  it('keeps every live denial and no stale one across a write that sweeps', async () => {
    upstream.introspect({ active: false });
    const { checker } = makeChecker(10_000);
    const [first, second, third] = cacheTokens;
    if (first === undefined || second === undefined || third === undefined) {
      throw new Error('the sweep needs three distinct tokens');
    }

    // Cached until +10_000.
    await expectRejectedClass(check(checker, first), 'unauthorized', 'first token');
    expect(introspectionCalls().length).toBe(1);

    // Cached until +14_000.
    clockMs = START_MS + 4_000;
    await expectRejectedClass(check(checker, second), 'unauthorized', 'second token');
    expect(introspectionCalls().length).toBe(2);

    // This write sweeps: the first token's entry is expired, the second's is not.
    clockMs = START_MS + 11_000;
    await expectRejectedClass(check(checker, third), 'unauthorized', 'third token');
    expect(introspectionCalls().length).toBe(3);

    await expectRejectedClass(check(checker, second), 'unauthorized', 'a live denial survives');
    expect(
      introspectionCalls().length,
      'a sweep dropping a live denial would let a revoked grant back in for the rest of its window'
    ).toBe(3);

    await expectRejectedClass(
      check(checker, first),
      'unauthorized',
      'an expired denial is re-asked'
    );
    expect(introspectionCalls().length, 'and a stale entry must not be reused').toBe(4);

    clockMs = START_MS + 15_000;
    await expectRejectedClass(check(checker, second), 'unauthorized', 'once it too expires');
    expect(introspectionCalls().length).toBe(5);
  });
});

describe('what actually goes on the wire', () => {
  it('sends the access-token VALUE, the hint and a verifiable client assertion', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker();

    await expect(check(checker)).resolves.toBeDefined();

    const calls = introspectionCalls();
    expect(calls.length, 'an assertion about the wire needs a request on it').toBe(1);
    const call = calls[0];
    if (call === undefined) throw new Error('unreachable: the assertion above fails first');

    expect(call.method).toBe('POST');

    const form = formOf(call);
    expect(
      form.get('token'),
      'RFC 7662 over the presented access-token value — a jti alone is not introspection'
    ).toBe(accessToken);
    expect(form.get('token'), 'the token value is a compact JWS, not an identifier').toContain('.');
    expect(form.get('token')).not.toBe('jti-under-test');
    expect(form.get('token_type_hint')).toBe('access_token');
    expect(form.get('client_assertion_type')).toBe(CLIENT_ASSERTION_TYPE);

    const assertion = form.get('client_assertion') ?? '';
    const { payload } = await jwtVerify(assertion, assertionKey.publicKey, {
      currentDate: new Date(clockMs),
    });
    expect(payload.iss, 'the assertion is signed by this server, as itself').toBe(CLIENT_ID);
    expect(payload.sub).toBe(CLIENT_ID);
    expect(payload.aud, 'and is accepted only by the endpoint it names').toBe(INTROSPECTION_URL);
  });

  it('carries the correlation identifier and the form content type, and no credential header', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker();

    await expect(check(checker)).resolves.toBeDefined();

    const call = introspectionCalls()[0];
    if (call === undefined) throw new Error('no introspection request reached the wire');

    const headers = headersOf(call);
    expect(headers.get('content-type')).toContain('application/x-www-form-urlencoded');
    expect(headers.get(CORRELATION_ID_HEADER), 'one identifier spans the whole request').toBe(
      CORRELATION_ID
    );
    expect(
      headers.get('authorization'),
      'this server authenticates by an assertion in the body; a bearer header here would be the inbound token forwarded'
    ).toBeUndefined();
    expect(headers.get('cookie')).toBeUndefined();
  });

  it('never puts the inbound token in the URL', async () => {
    upstream.introspect({ ...ACTIVE_PAYLOAD });
    const { checker } = makeChecker();

    await expect(check(checker)).resolves.toBeDefined();

    const call = introspectionCalls()[0];
    if (call === undefined) throw new Error('no introspection request reached the wire');

    expect(call.fullUrl, 'a credential in a query string lands in every access log').not.toContain(
      accessToken
    );
    expect(call.searchParams).toEqual({});
  });
});
