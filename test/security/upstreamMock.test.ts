/**
 * Security suite: the shared upstream mock, driven as a control instead of trusted as one.
 * Ticket 63.
 *
 * `test/support/upstreamMock.ts` is what stops every other suite reaching the real network. It
 * intercepted nothing for as long as it existed: the package was 8.x while the pinned Node ships
 * 7.x. Package 8 registers its agent on its own symbol *and* a lossy wrapper on the legacy symbol
 * the runtime reads, so requests were **recorded and then escaped** — which is why bodies arrived
 * as streams and why nothing went red.
 *
 * **Not every major skew does this.** Package 7 on a runtime shipping 6 writes the same agent to
 * both symbols and still intercepts, measured. Package 8 on runtime 7 is the only pairing proven
 * broken; the major-equality case below is a policy about a silent failure whose safe pairings
 * cannot be enumerated.
 *
 * **This suite is green**, unlike the rest of `test/security/**`, and needs no `src/` module. A
 * red row here is a live hole under every absence assertion in the security layer: report it,
 * never skip it. Each case discriminates against a green-looking twin — see the note on each.
 */

import { readFileSync } from 'node:fs';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { fetch as packagedFetch } from 'undici';
import { createTestKeyPair, type TestKeyPair } from '../../scripts/makeToken.ts';
import { expectWireCalls } from '../support/assertions.ts';
import {
  installUpstreamMock,
  type JwksOutcome,
  type UpstreamMock,
} from '../support/upstreamMock.ts';
import {
  FOODDATA_SEARCH_PATH,
  MCP_JWKS_URL,
  MEALPLAN_ME_PATH,
  NUTRIHELP_API_ORIGIN,
} from '../support/testEnv.ts';

/**
 * The subject under test. `setGlobalDispatcher` swaps the dispatcher this function reaches, not
 * the function, so capturing it once is equivalent to reading it per call. The disable is the
 * point of the file, not a hole: routing these cases through the `undici` export instead would
 * pass under exactly the pairing this suite exists to catch.
 */
// eslint-disable-next-line no-restricted-syntax -- the runtime's own fetch is the subject
const runtimeFetch = globalThis.fetch;

/** Not `{}`, and distinctive enough that a coerced or truncated body cannot coincide with it. */
const REQUEST_BODY = JSON.stringify({
  probe: 'upstream-mock-body-fidelity-9f2c',
  nested: { count: 3, flag: true },
});

const CANNED_REPLY = { data: [{ food_name: 'Apple', energy_kj: 218 }] };

/** Registered on no route, so it can only be answered by the mock refusing it. */
const UNMATCHED_URL = `${NUTRIHELP_API_ORIGIN}/api/never-registered-route`;

const JWKS_PATH = new URL(MCP_JWKS_URL).pathname;

/** Sentinel for a `publishKeys` that returned. Mirrors the rejection sentinel below it. */
const NO_REFUSAL = 'publishKeys returned rather than refusing';

let key: TestKeyPair;
let rotatedKey: TestKeyPair;
let upstream: UpstreamMock;

beforeAll(async () => {
  key = await createTestKeyPair('mcp-signing-key-1');
  rotatedKey = await createTestKeyPair('mcp-signing-key-2');
});

beforeEach(() => {
  upstream = installUpstreamMock([key]);
});

afterEach(async () => {
  await upstream.restore();
});

/** Never stringify an object of unknown shape: `[object Object]` would hide the discriminator. */
function readString(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback;
}

/**
 * The discriminator lives in `error.cause`, which is `unknown`. No depth cap: a fixed one would
 * truncate silently if a release nested the refusal deeper, turning "discriminator missing" into
 * a false red. The visited set is what makes the unbounded walk safe against a cyclic chain.
 */
function describeFailure(error: unknown): string {
  const parts: string[] = [];
  const seen = new Set<object>();
  let current: unknown = error;
  while (current !== null && current !== undefined) {
    if (typeof current !== 'object') {
      parts.push(readString(current, `non-object rejection of type ${typeof current}`));
      break;
    }
    if (seen.has(current)) break;
    seen.add(current);
    const shaped = current as {
      name?: unknown;
      message?: unknown;
      code?: unknown;
      cause?: unknown;
    };
    const name = readString(shaped.name, 'unnamed');
    const code = readString(shaped.code, 'no-code');
    parts.push(`${name}(${code}): ${readString(shaped.message, '')}`);
    current = shaped.cause;
  }
  return parts.join(' <- ');
}

/** Resolve to the rejection reason. `rejects.toThrow()` alone cannot discriminate the cause. */
async function captureRejection(promise: Promise<unknown>): Promise<unknown> {
  const NO_REJECTION = Symbol('no rejection');
  const outcome: unknown = await promise.then(
    () => NO_REJECTION,
    (reason: unknown) => reason
  );
  expect(
    outcome,
    'an unmatched request under disableNetConnect() must reject. A resolved response means something answered it, and the only thing that could is the network'
  ).not.toBe(NO_REJECTION);
  return outcome;
}

/** Read served key ids through runtime fetch. */
async function servedKids(url: string): Promise<string[]> {
  const response = await runtimeFetch(url);
  expect(
    response.status,
    'the in-test JWKS route must answer, or a rotation assertion below is comparing two failures'
  ).toBe(200);
  const document: unknown = await response.json();
  const entries = (document as { keys?: readonly { kid?: unknown }[] }).keys ?? [];
  return entries.map((entry) => readString(entry.kid, 'kid-absent'));
}

/** Nested install/restore so the outer fixture survives; returns refusal message or NO_REFUSAL. */
async function refusalMessage(keys: readonly TestKeyPair[], jwks: JwksOutcome): Promise<string> {
  const mock = installUpstreamMock(keys, { jwks });
  try {
    mock.publishKeys(keys);
    return NO_REFUSAL;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  } finally {
    await mock.restore();
  }
}

describe('the shared upstream mock', () => {
  /**
   * Twin: the package's own `fetch` export is intercepted under both pairings, so driving the
   * harness through it proves nothing. The identity check asserts the two are distinct rather
   * than assuming it — if they were ever the same object this file would prove nothing either.
   */
  it('serves a matched request to the runtime fetch, not merely to the undici export', async () => {
    expect(
      runtimeFetch,
      "the runtime's fetch and the undici package's export must be distinct functions. If they are not, every case in this file is testing the package instead of the runtime and proves nothing"
    ).not.toBe(packagedFetch);

    upstream.route({
      path: new RegExp(`^${FOODDATA_SEARCH_PATH}(\\?.*)?$`),
      status: 200,
      body: CANNED_REPLY,
    });

    const response = await runtimeFetch(`${NUTRIHELP_API_ORIGIN}${FOODDATA_SEARCH_PATH}?q=apple`);

    expect(
      response.status,
      'a routed request must be answered by the mock. Anything else means the dispatcher swap never reached this fetch'
    ).toBe(200);
    expect(
      await response.json(),
      'the canned reply must come back verbatim, so a suite that asserts on a response is asserting on the fixture it registered'
    ).toEqual(CANNED_REPLY);
  });

  /**
   * Twin: an unmatched request throws either way — `MockNotMatchedError` when the mock is live,
   * `ENOTFOUND` when it is not and the request died in the resolver. "It threw" is satisfied by
   * both, so the cause is pinned in both directions. A `.test` hostname failing to resolve is
   * why the broken pairing was survivable; it is not a control.
   */
  it('refuses an unmatched request rather than attempting a real connection', async () => {
    const error = await captureRejection(runtimeFetch(UNMATCHED_URL));
    const detail = describeFailure(error);

    expect(detail, `an unmatched request must be refused by the mock. Got: ${detail}`).toContain(
      'UND_MOCK_ERR_MOCK_NOT_MATCHED'
    );
    expect(
      detail,
      `the refusal must be disableNetConnect() declining to connect. Got: ${detail}`
    ).toContain('net.connect disabled');

    for (const dnsMarker of ['ENOTFOUND', 'getaddrinfo', 'EAI_AGAIN', 'ECONNREFUSED']) {
      expect(
        detail,
        `the request reached the resolver, so nothing was intercepted and it failed only because the hostname does not exist. Got: ${detail}`
      ).not.toContain(dnsMarker);
    }
  });

  /**
   * Twin: a body arrived as an `AsyncGenerator` and was coerced to `"{}"` — defined, truthy and
   * wrong. Every "never reached the wire" assertion in the security layer reads `WireCall.body`,
   * so all of them were vacuously green. Exact equality against a payload that is not `{}` is
   * the only comparison that catches it.
   */
  it('records the exact request body that was sent', async () => {
    expect(
      REQUEST_BODY,
      'the fixture must not be an empty object literal: a coerced body renders as "{}" and would satisfy the comparison below'
    ).not.toBe('{}');

    upstream.route({
      path: new RegExp(`^${MEALPLAN_ME_PATH}(\\?.*)?$`),
      method: 'POST',
      status: 200,
      body: { ok: true },
    });

    await runtimeFetch(`${NUTRIHELP_API_ORIGIN}${MEALPLAN_ME_PATH}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: REQUEST_BODY,
    });

    const calls = expectWireCalls(
      upstream.callsTo(MEALPLAN_ME_PATH),
      'body fidelity: the POST must be recorded before its body can be compared'
    );
    // Narrow rather than reach through `?.`, so dropping the guard above fails here instead of
    // quietly comparing against undefined.
    const call = calls[0];
    expect(call, 'the guard above establishes this call exists').toBeDefined();
    if (call === undefined) throw new Error('unreachable: the assertion above fails first');

    expect(call.method, 'the recorded call must be the POST that was just made').toBe('POST');
    expect(
      call.body,
      'the recorded body must be the exact string sent. A coerced or re-serialised body makes every absence assertion over WireCall.body meaningless'
    ).toBe(REQUEST_BODY);
  });

  /** Assert the old kid disappears after publishKeys — presence-only checks miss a frozen body. */
  it('serves the rotated key set to a later request, and stops serving the old one', async () => {
    expect(
      rotatedKey.kid,
      'the two fixtures must carry distinct identifiers, or neither assertion below can tell the sets apart'
    ).not.toBe(key.kid);

    expect(
      await servedKids(MCP_JWKS_URL),
      'the endpoint must serve the installed set first, or the rotation below has nothing to replace'
    ).toEqual([key.kid]);

    upstream.publishKeys([rotatedKey]);

    const after = await servedKids(MCP_JWKS_URL);
    expect(
      after,
      'the rotated set must be served from here on. A body built once at install time answers with the startup set forever, and every rotation test then passes against keys that never changed'
    ).toEqual([rotatedKey.kid]);

    // Counted rather than inferred: an intercept that stopped persisting would fail the second
    // read outright, but a response served from anywhere other than this route would not.
    expect(
      upstream.callsTo(JWKS_PATH),
      'both reads must have reached the mocked route, or the sets compared above came from somewhere this harness does not control'
    ).toHaveLength(2);
  });

  /** Fixed-body and unreachable jwks outcomes must refuse with distinct messages. */
  it('refuses to rotate a supplied jwks outcome, and says which kind it is refusing', async () => {
    const fixedBody = await refusalMessage([key], { status: 200, body: { keys: [] } });
    const unreachable = await refusalMessage([key], 'unreachable');

    for (const [label, message] of [
      ['a fixed-body outcome', fixedBody],
      ['an unreachable outcome', unreachable],
    ] as const) {
      expect(
        message,
        `publishKeys must refuse ${label}: rotating one silently keeps the old set in play while the test reads as a rotation`
      ).not.toBe(NO_REFUSAL);
    }

    expect(
      fixedBody,
      'the fixed-body refusal must name the body that keeps being served, which is why that rotation cannot take effect'
    ).toContain('fixed body');
    expect(
      unreachable,
      'the unreachable refusal must say that no intercept is registered. Describing a fixed-body route here explains a route the developer never registered'
    ).toContain('No JWKS intercept is registered');
    expect(
      fixedBody,
      'the two outcomes fail for different reasons, so one message serving both is the defect this case exists to catch'
    ).not.toBe(unreachable);
  });

  /**
   * The same regression named at its cause, so a red run above has a one-line diagnosis rather
   * than an investigation. `undici` is one of the few dependencies that also exists inside Node.
   */
  it('is installed at the same undici major the runtime ships internally', () => {
    const manifestUrl = new URL('../../node_modules/undici/package.json', import.meta.url);
    const manifest: unknown = JSON.parse(readFileSync(manifestUrl, 'utf8'));
    const installed = readString((manifest as { version?: unknown }).version, '');
    const runtime = readString(process.versions.undici, '');

    // Positive controls: a bad path walk, a renamed field or an absent runtime version would
    // otherwise leave the comparison below reading '' against '' and passing forever.
    expect(
      installed,
      'the installed undici version must be readable, or the comparison below asserts nothing'
    ).not.toBe('');
    expect(
      runtime,
      "the runtime's own undici version must be readable, or the comparison below asserts nothing"
    ).not.toBe('');

    const major = (version: string): string => version.split('.')[0] ?? '';

    expect(
      major(installed),
      `declared undici (${installed}) must share a major with the copy inside Node (${runtime}). Package 8 on runtime 7 leaves requests recorded but never intercepted, so every mock in the suite goes blind while the assertions keep passing. Equality is required because that failure is silent and the safe pairings cannot be enumerated`
    ).toBe(major(runtime));
  });
});
