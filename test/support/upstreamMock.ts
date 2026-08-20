/**
 * An `undici` `MockAgent` on the global dispatcher, plus a record of every request.
 *
 * **`src/upstream/client.ts` is never mocked** — the transport beneath it is. Mocking the
 * client would hide the deny-list, which lives inside it.
 *
 * `disableNetConnect()` is on. Call history records every dispatch, matched or not.
 *
 * **Keep the `undici` major equal to `process.versions.undici`.** Correctness, not hygiene: a
 * mismatch can stop `setGlobalDispatcher` reaching `globalThis.fetch`, and the mock then goes
 * blind while every gate stays green. `test/security/upstreamMock.test.ts` is the guard and
 * carries the account; if it is red, nothing here is evidence about the wire.
 */

import { MockAgent, getGlobalDispatcher, setGlobalDispatcher, type Dispatcher } from 'undici';
import { toJwks, type TestKeyPair } from '../../scripts/makeToken.ts';
import {
  AUTH_SERVER_ORIGIN,
  INTROSPECTION_PATH,
  MCP_JWKS_URL,
  NUTRIHELP_API_ORIGIN,
  TOKEN_EXCHANGE_PATH,
} from './testEnv.ts';

export interface WireCall {
  readonly method: string;
  readonly origin: string;
  /** Path without the query string. */
  readonly path: string;
  readonly fullUrl: string;
  readonly searchParams: Record<string, string>;
  readonly headers: Record<string, string | string[]>;
  readonly body: string;
}

export interface RouteSpec {
  readonly origin?: string;
  /**
   * undici matches this against the path INCLUDING the query string, so a literal string fails
   * to match a handler that correctly sends `?date=...` — surfacing as `MockNotMatchedError`,
   * i.e. "the tool returned nothing" rather than "the mock is too strict". Use a regex unless
   * the query is what you are asserting.
   */
  readonly path: string | RegExp;
  readonly method?: string;
  readonly status: number;
  /** Serialised as the JSON response body. `object` is what the MockAgent reply signature takes. */
  readonly body: object | string;
  /** Answer one call only. Routes are registered indefinitely by default. */
  readonly once?: boolean;
}

/**
 * How the in-test JWKS endpoint answers.
 *
 * A key set that cannot be consulted is a different answer from a credential that failed, so the
 * suite has to be able to produce one — and it has to come from this endpoint rather than from a
 * faked validator, because the classification under test reads what the real library throws.
 *
 * `'unreachable'` registers no intercept at all: `disableNetConnect()` then refuses the request
 * before it can leave, which is the shape a refused connection or a DNS failure arrives in.
 *
 * Replaces the default route rather than adding to it. undici answers from the first registered
 * interceptor that matches and the default one is `.persist()`ed, so a second route for the same
 * path would never be reached.
 */
export type JwksOutcome =
  | {
      readonly status: number;
      readonly body: object | string;
      /**
       * Hold the reply for this long before sending it. How a deadline case gets a slow endpoint
       * without waiting on a real one — the budget under test is milliseconds, so the delay is too.
       */
      readonly delayMs?: number;
    }
  | 'unreachable';

export interface UpstreamMockOptions {
  /** Default: 200 carrying the key set built from `keys`. */
  readonly jwks?: JwksOutcome;
}

export interface UpstreamMock {
  /** Every request that reached the wire, in order, matched or not. */
  wireCalls(): WireCall[];
  /** Wire calls whose path starts with `prefix`. */
  callsTo(prefix: string): WireCall[];
  /** Register a canned upstream response. */
  route(spec: RouteSpec): void;
  /** RFC 7662 introspection reply. */
  introspect(payload: Record<string, unknown>, status?: number): void;
  /** RFC 8693 token-exchange reply. */
  exchange(payload: Record<string, unknown>, status?: number): void;
  /** Replace the JWKS key set from here on; refuses when a `jwks` outcome was supplied. */
  publishKeys(keys: readonly TestKeyPair[]): void;
  restore(): Promise<void>;
}

const JWKS_PATH = new URL(MCP_JWKS_URL).pathname;

/**
 * Coercing an unrecognised body shape to `''` makes every body-side absence assertion trivially
 * true, and form-encoded introspection and exchange hit exactly that. Throw instead.
 *
 * The `object` branch is the sharp edge: a mismatched `undici` major delivers bodies as an
 * `AsyncGenerator`, which serialises to `"{}"` — defined, truthy, and wrong.
 */
function renderBody(body: unknown): string {
  if (body === undefined || body === null) return '';
  if (typeof body === 'string') return body;
  if (Buffer.isBuffer(body)) return body.toString('utf8');
  if (body instanceof URLSearchParams) return body.toString();
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer as ArrayBuffer).toString('utf8');
  // Reject by type before serialising: JSON.stringify is typed as returning `string`, so a
  // check against undefined is dead code.
  if (typeof body === 'object') return JSON.stringify(body);
  throw new Error(
    `upstreamMock: unrenderable request body of type ${typeof body}. Absence assertions over ` +
      'this call would be vacuous, so the harness fails instead of reporting a false green.'
  );
}

function readHistory(agent: MockAgent): WireCall[] {
  const history = agent.getCallHistory();
  if (history === undefined) return [];
  return history.calls().map((log) => ({
    method: log.method,
    origin: log.origin,
    path: log.path,
    fullUrl: log.fullUrl,
    searchParams: log.searchParams,
    headers: log.headers ?? {},
    body: renderBody(log.body),
  }));
}

/**
 * Install the mock. `keys` are published from an in-test JWKS intercept; verification keys are
 * never fetched over the network.
 */
export function installUpstreamMock(
  keys: readonly TestKeyPair[],
  options: UpstreamMockOptions = {}
): UpstreamMock {
  const previous: Dispatcher = getGlobalDispatcher();
  const agent = new MockAgent({ enableCallHistory: true });
  agent.disableNetConnect();
  setGlobalDispatcher(agent);

  // Default JWKS body resolves per request so publishKeys can rotate under a cached validator.
  const fixedJwks = options.jwks;
  let publishedKeys: readonly TestKeyPair[] = keys;

  if (fixedJwks !== 'unreachable') {
    const body: object | string | (() => object) = fixedJwks?.body ?? (() => toJwks(publishedKeys));
    const reply = agent
      .get(AUTH_SERVER_ORIGIN)
      .intercept({ path: JWKS_PATH, method: 'GET' })
      .reply(fixedJwks?.status ?? 200, body, {
        headers: { 'content-type': 'application/json' },
      });
    if (fixedJwks?.delayMs !== undefined) reply.delay(fixedJwks.delayMs);
    reply.persist();
  }

  function route(spec: RouteSpec): void {
    const scope = agent
      .get(spec.origin ?? NUTRIHELP_API_ORIGIN)
      .intercept({ path: spec.path, method: spec.method ?? 'GET' })
      .reply(spec.status, spec.body, { headers: { 'content-type': 'application/json' } });
    if (spec.once !== true) scope.persist();
  }

  return {
    wireCalls: () => readHistory(agent),
    callsTo: (prefix: string) => readHistory(agent).filter((call) => call.path.startsWith(prefix)),
    route,
    introspect(payload, status = 200) {
      route({
        origin: AUTH_SERVER_ORIGIN,
        path: INTROSPECTION_PATH,
        method: 'POST',
        status,
        body: payload,
      });
    },
    exchange(payload, status = 200) {
      route({
        origin: AUTH_SERVER_ORIGIN,
        path: TOKEN_EXCHANGE_PATH,
        method: 'POST',
        status,
        body: payload,
      });
    },
    publishKeys(next: readonly TestKeyPair[]): void {
      // Two refusals, not one. Conflating them hands the developer an explanation of a route that
      // does not exist on the path where no route was ever registered.
      if (fixedJwks === 'unreachable') {
        throw new Error(
          "upstreamMock: publishKeys cannot rotate an 'unreachable' `jwks` outcome. No JWKS " +
            'intercept is registered, so every key-set request is refused before anything answers ' +
            'it: no set is being served and there is nothing for the new keys to replace. Drop ' +
            'the outcome to rotate against a live endpoint.'
        );
      }
      if (fixedJwks !== undefined) {
        throw new Error(
          'upstreamMock: publishKeys cannot rotate a supplied `jwks` outcome. That route answers ' +
            'a fixed body, so the new keys would never be served and the test would assert ' +
            'against the old set while reading as a rotation.'
        );
      }
      publishedKeys = next;
    },
    async restore(): Promise<void> {
      setGlobalDispatcher(previous);
      await agent.close();
    },
  };
}

/** URL, headers and body as one searchable string: a field can be smuggled in any of them. */
export function wireCallText(call: WireCall): string {
  return [call.fullUrl, JSON.stringify(call.headers), call.body].join('\n');
}
