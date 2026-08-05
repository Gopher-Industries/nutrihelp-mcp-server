/**
 * Behavioural assertions: status, challenge headers, JSON-RPC envelope, requests that did or
 * did not happen. Nothing names a class — that is what lets the suite precede the code.
 */

import { expect } from 'vitest';
import { RESOURCE_METADATA_URL } from './testEnv.ts';
import { toolResult, type McpResponse, type ToolResultView } from './mcpClient.ts';
import type { WireCall } from './upstreamMock.ts';

function describeResponse(response: McpResponse): string {
  return `HTTP ${String(response.status)}, www-authenticate=${response.challenge ?? '(absent)'}, body=${response.rawBody.slice(0, 300)}`;
}

/** 401 + Bearer challenge carrying `resource_metadata`. Also the one introspection outcome
 *  that maps here: an authenticated `active: false`. */
export function expectUnauthorizedChallenge(response: McpResponse, context: string): void {
  expect(
    response.status,
    `${context}: plan §6.5 maps this to 401. Got ${describeResponse(response)}`
  ).toBe(401);
  expect(
    response.challenge,
    `${context}: plan §5.4 requires WWW-Authenticate on a 401 from /mcp. Got ${describeResponse(response)}`
  ).toBeDefined();
  const challenge = response.challenge ?? '';
  expect(challenge, `${context}: the challenge scheme must be Bearer`).toMatch(/^Bearer\b/i);
  expect(challenge, `${context}: plan §6.5 requires resource_metadata in the challenge`).toContain(
    'resource_metadata'
  );
  expect(challenge, `${context}: resource_metadata must name the RFC 9728 document`).toContain(
    RESOURCE_METADATA_URL
  );
}

/** 403 insufficient_scope, before dispatch, carrying the required scope. */
export function expectInsufficientScopeChallenge(
  response: McpResponse,
  requiredScope: string,
  context: string
): void {
  expect(
    response.status,
    `${context}: plan §6.5 maps insufficient scope to 403, not 401. Got ${describeResponse(response)}`
  ).toBe(403);
  const challenge = response.challenge ?? '';
  expect(challenge, `${context}: plan §6.5 requires error="insufficient_scope"`).toContain(
    'insufficient_scope'
  );
  expect(challenge, `${context}: plan §6.5 requires the required scope in the challenge`).toContain(
    requiredScope
  );
  expect(challenge, `${context}: plan §6.5 requires resource_metadata in the challenge`).toContain(
    'resource_metadata'
  );
}

/**
 * Every introspection outcome except `active: false` fails as the retryable class, NOT as a
 * 401 — otherwise an authorization-server outage loops every client through refresh-and-retry.
 */
export function expectNotAnAuthChallenge(response: McpResponse, context: string): void {
  expect(
    response.status,
    `${context}: plan §4.9 — active:false is the ONLY introspection outcome mapped to 401. Got ${describeResponse(response)}`
  ).not.toBe(401);
  expect(
    response.challenge,
    `${context}: a Bearer challenge here would push the client into refresh-and-retry. Plan §4.9`
  ).toBeUndefined();
}

/**
 * Narrow to the model-facing tool result. An `expect` rather than a throw, so a failure reads
 * as an assertion about behaviour rather than a harness crash.
 */
export function expectToolResult(response: McpResponse, context: string): ToolResultView {
  const view = toolResult(response);
  expect(
    view,
    `${context}: expected a tools/call result. Got ${describeResponse(response)}`
  ).toBeDefined();
  if (view === undefined) throw new Error('unreachable: the assertion above fails first');
  return view;
}

/** "The field never reached the wire" is trivially true when nothing reached the wire. */
export function expectWireCalls(calls: readonly WireCall[], context: string): readonly WireCall[] {
  expect(
    calls.length,
    `${context}: expected at least one upstream request. An "absent from the wire" assertion over zero requests proves nothing.`
  ).toBeGreaterThan(0);
  return calls;
}

/**
 * The same guard inside a loop. `expectWireCalls` reads cumulative history, so iteration n is
 * satisfied by iteration 1's call. Pass the length captured before the action; assertions run
 * over the delta only.
 */
export function expectWireCallsSince(
  calls: readonly WireCall[],
  before: number,
  context: string
): readonly WireCall[] {
  const fresh = calls.slice(before);
  expect(
    fresh.length,
    `${context}: expected at least one NEW upstream request from this step. Earlier iterations do not count — an absence assertion over stale history proves nothing.`
  ).toBeGreaterThan(0);
  return fresh;
}
