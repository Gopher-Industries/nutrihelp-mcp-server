/**
 * An `undici` `MockAgent` on the global dispatcher, plus a record of every request.
 *
 * **`src/upstream/client.ts` is never mocked** — the transport beneath it is. Mocking the
 * client would hide the deny-list, which lives inside it.
 *
 * `disableNetConnect()` is on. Call history records every dispatch, matched or not.
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
  readonly path: string | RegExp;
  readonly method?: string;
  readonly status: number;
  /** Serialised as the JSON response body. `object` is what the MockAgent reply signature takes. */
  readonly body: object | string;
  /** Answer one call only. Routes are registered indefinitely by default. */
  readonly once?: boolean;
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
  restore(): Promise<void>;
}

const JWKS_PATH = new URL(MCP_JWKS_URL).pathname;

/**
 * Coercing an unrecognised body shape to `''` makes every body-side absence assertion trivially
 * true, and form-encoded introspection and exchange hit exactly that. Throw instead.
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
export function installUpstreamMock(keys: readonly TestKeyPair[]): UpstreamMock {
  const previous: Dispatcher = getGlobalDispatcher();
  const agent = new MockAgent({ enableCallHistory: true });
  agent.disableNetConnect();
  setGlobalDispatcher(agent);

  // JWKS, served in-test. Persisted: a validator may refetch on an unknown key identifier.
  agent
    .get(AUTH_SERVER_ORIGIN)
    .intercept({ path: JWKS_PATH, method: 'GET' })
    .reply(200, toJwks(keys), { headers: { 'content-type': 'application/json' } })
    .persist();

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
