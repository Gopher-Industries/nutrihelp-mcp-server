/**
 * `Mcp-Method` and `Mcp-Name`: which values reach a scope decision and which are refused outright.
 *
 * These headers are trusted for exactly one thing — selecting a scope requirement — and selecting
 * it IS trust. The handler compares them against the body afterwards, which catches a disagreement
 * only after a verdict has already been computed here. So a value is refused unless it is already
 * in the plain form the handler would resolve it to.
 *
 * The table runs BOTH directions. A refusal-only table is passed in full by an endpoint that
 * refuses every routing value it is ever shown, and such an endpoint serves nothing.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { connect } from 'node:net';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../scripts/makeToken.ts';
import {
  closeLocalDispatcher,
  mcpRequest,
  startTestServer,
  type McpResponse,
  type TestServer,
} from '../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../support/upstreamMock.ts';
import {
  ALL_SCOPES,
  ALLOWED_ORIGIN,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  USER_A,
} from '../support/testEnv.ts';

/** The code the transport emits when it refuses a routing value. Present in the reported errors
 *  when the GUARD refused, and absent when something in front of it did — which is how the raw
 *  socket cases below say which layer held the property. */
const ROUTING_REFUSAL_CODE = 'bad_request.routing_header_not_plain';

let trustedKey: TestKeyPair;
let token: string;
let server: TestServer;
let upstream: UpstreamMock;
let dispatches: number;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  token = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    sub: USER_A,
  });
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  dispatches = 0;
  server = await startTestServer({
    onDispatch: () => {
      dispatches += 1;
    },
  });
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

/**
 * Reached the MCP handler. A positive discriminator, not a status exclusion: only the JSON-RPC
 * layer echoes the request id, and every refusal in front of it answers with no body at all.
 */
function expectReachedDispatch(response: McpResponse, context: string): void {
  expect(
    response.rpc?.id,
    `${context}: the request must reach the JSON-RPC dispatcher, which echoes the request id. Every pre-dispatch refusal answers with an empty body`
  ).toBe(1);
  expect(dispatches, `${context}: the MCP handler must have been built for this request`).toBe(1);
  expect(response.status, `${context}: not a routing refusal`).not.toBe(400);
  expect(server.errors.map((error) => error.message)).not.toContain(ROUTING_REFUSAL_CODE);
}

/** Refused by the routing guard specifically, rather than by anything else that also answers 400. */
function expectRefusedByRoutingGuard(response: McpResponse, context: string): void {
  expect(response.status, `${context}: a malformed routing value is a bad request`).toBe(400);
  expect(
    response.challenge,
    `${context}: no Bearer challenge — this says nothing about the credential, and reauthorizing cannot fix a malformed header`
  ).toBeUndefined();
  expect(
    server.errors.map((error) => error.message),
    `${context}: refused BY THE ROUTING GUARD, not by a layer in front of it`
  ).toContain(ROUTING_REFUSAL_CODE);
  expect(dispatches, `${context}: refused before dispatch`).toBe(0);
}

/** Every value that must reach a scope decision. Nothing in this server's surface needs encoding,
 *  so this list is the whole plain shape: a method name and two tool-name spellings. */
const ACCEPTED = [
  { label: 'a method name', method: 'tools/list', name: undefined },
  { label: 'an underscored tool name', method: 'tools/call', name: 'nutrition_lookup' },
  { label: 'a hyphenated tool name', method: 'tools/call', name: 'get-meal-plan' },
] as const;

/** Every value that must be refused, with what it is trying to do. */
const REFUSED = [
  {
    label: 'the encoded sentinel form',
    value: '=?utf-8?B?dG9vbHMvbGlzdA==?=',
    why: 'the handler decodes this before comparing against the body, so a scope requirement selected from the undecoded string is selected from the wrong name',
  },
  {
    label: 'a comma-joined duplicate header',
    value: 'tools/list, tools/call',
    why: 'Node joins duplicate headers with ", ", so two Mcp-Name values must fail rather than resolve from a concatenation',
  },
  {
    label: 'a space-joined value',
    value: 'tools/list tools/call',
    why: 'a space is how a second value hides inside one header',
  },
  {
    label: 'a percent-encoded separator',
    value: 'tools%2Flist',
    why: 'percent-encoding is a second spelling of a name, and two spellings of one name is what the plain-form rule exists to prevent',
  },
  {
    label: 'a bare percent sign',
    value: 'tools/list%',
    why: 'a truncated escape decodes differently in every reader that tries',
  },
  {
    label: 'a horizontal tab',
    value: 'tools/list\tx',
    why: 'a tab is legal in a header value and arrives at the application intact, so nothing but this guard refuses it',
  },
  {
    label: 'a leading underscore',
    value: '_tools',
    why: 'the plain form starts with a letter',
  },
  { label: 'a leading slash', value: '/tools/list', why: 'the plain form starts with a letter' },
  { label: 'a leading digit', value: '1tools', why: 'the plain form starts with a letter' },
  {
    label: 'an empty value',
    value: '',
    why: 'an absent header is legitimate; a header present and empty is not the same thing',
  },
  {
    label: 'a non-ASCII letter',
    value: 'tools/lXst'.replace('X', String.fromCharCode(0xef)),
    why: 'a homoglyph is a different name that reads as the right one',
  },
  {
    label: 'a colon',
    value: 'resource:read',
    why: 'the plain form excludes the colon, which scopes it to method and tool names. A capability whose name mirrors a URI would take this 400, and this row is what forces that decision to be made in the change that adds one rather than after it',
  },
] as const;

describe('routing header values that must reach a scope decision', () => {
  it.each(ACCEPTED)('accepts $label', async ({ method, name }) => {
    const response = await mcpRequest(server, {
      method,
      ...(name === undefined ? {} : { name, params: { name, arguments: {} } }),
      token,
    });

    expectReachedDispatch(response, `${method} / ${name ?? '(no name)'}`);
  });

  it('keeps a floor under the accepted table', () => {
    expect(
      ACCEPTED.length,
      'anti-vacuity: with no accepted rows, an endpoint that refuses every routing value passes this whole file'
    ).toBeGreaterThanOrEqual(3);
  });
});

describe('routing header values that must be refused', () => {
  it.each(REFUSED)('refuses $label as Mcp-Name', async ({ value, why }) => {
    const response = await mcpRequest(server, {
      method: 'tools/call',
      nameHeader: value,
      params: { name: 'nutrition_lookup', arguments: {} },
      token,
    });

    expectRefusedByRoutingGuard(response, `Mcp-Name: ${why}`);
  });

  /**
   * The same values in the other header. The shape is checked whether or not anything reads the
   * value today, so gating either header on the presence of a scope resolver would leave the next
   * reader of these values inheriting an unvalidated name.
   */
  it.each(REFUSED)('refuses $label as Mcp-Method', async ({ value, why }) => {
    const response = await mcpRequest(server, {
      method: 'tools/list',
      methodHeader: value,
      token,
    });

    expectRefusedByRoutingGuard(response, `Mcp-Method: ${why}`);
  });

  /**
   * The token is valid in every refused case above, and that is the point: a 401 anywhere in this
   * block would mean the credential was read first, and the scope requirement these headers select
   * would then have been chosen from a value nothing had checked.
   */
  it('refuses a malformed routing value ahead of the credential', async () => {
    const withToken = await mcpRequest(server, {
      method: 'tools/list',
      methodHeader: '=?utf-8?B?eA==?=',
      token,
    });
    expect(withToken.status).toBe(400);

    // Reported errors are cumulative, so the second half of this case reads the delta rather than
    // the whole history: an assertion over cumulative state is satisfied by the first request.
    const reportsBefore = server.errors.length;

    const withoutToken = await mcpRequest(server, {
      method: 'tools/list',
      methodHeader: '=?utf-8?B?eA==?=',
    });
    expect(
      withoutToken.status,
      'the same 400 with no credential at all: the routing check does not depend on having read one'
    ).toBe(400);
    expect(withoutToken.challenge).toBeUndefined();
    expect(
      server.errors.slice(reportsBefore).map((error) => error.message),
      'the second request was refused by the routing guard too, not by the absent credential'
    ).toEqual([ROUTING_REFUSAL_CODE]);
    expect(dispatches, 'neither request dispatched').toBe(0);
  });

  it('keeps a floor under the refused table', () => {
    expect(
      REFUSED.length,
      'anti-vacuity: it.each([]) registers no tests and still exits 0, so emptying this table would quieten the suite rather than fail it'
    ).toBeGreaterThanOrEqual(12);
  });
});

/**
 * The three requirements the plain-form guard does NOT cover, and which this file's premise depends
 * on: a routing header must be present, and a present one must agree with the body.
 *
 * All three are refused by the SDK's own header rung rather than by the local guard, so every case
 * asserts the guard's code is ABSENT. That is what keeps the two layers legible — without it, a
 * later change that moved the check into the local guard, or deleted the SDK's, would be invisible.
 *
 * The disagreement case is the load-bearing one. Both values are plain, so the local guard passes
 * them through, and only the comparison against the body can refuse it. Until it existed, this
 * file's header asserted that comparison happens and nothing tested it.
 */
describe('routing headers that are absent or disagree with the body', () => {
  function expectRefusedByHeaderRung(response: McpResponse, context: string): void {
    expect(response.status, `${context}: refused as a bad request`).toBe(400);
    expect(dispatches, `${context}: refused before dispatch`).toBe(0);
    expect(
      server.errors.map((error) => error.message),
      `${context}: refused by the protocol header rung, not by the plain-form guard`
    ).not.toContain(ROUTING_REFUSAL_CODE);
  }

  it('refuses a request with no Mcp-Method header at all', async () => {
    const response = await mcpRequest(server, {
      method: 'tools/list',
      methodHeader: null,
      token,
    });

    expectRefusedByHeaderRung(response, 'Mcp-Method omitted');
  });

  it('refuses a named tool call with no Mcp-Name header', async () => {
    const response = await mcpRequest(server, {
      method: 'tools/call',
      nameHeader: null,
      params: { name: 'nutrition_lookup', arguments: {} },
      token,
    });

    expectRefusedByHeaderRung(response, 'Mcp-Name omitted on a named tool call');
  });

  it('refuses an Mcp-Name that disagrees with the body tool name', async () => {
    const response = await mcpRequest(server, {
      method: 'tools/call',
      nameHeader: 'get-meal-plan',
      params: { name: 'nutrition_lookup', arguments: {} },
      token,
    });

    expectRefusedByHeaderRung(
      response,
      'both values are plain, so only the comparison against the body can refuse this. A gateway may route on the header, and the application still never trusts it alone'
    );
  });

  it('refuses an Mcp-Method that disagrees with the body method', async () => {
    const response = await mcpRequest(server, {
      method: 'tools/list',
      methodHeader: 'tools/call',
      token,
    });

    expectRefusedByHeaderRung(response, 'Mcp-Method names an operation the body does not');
  });
});

/**
 * CR, LF and NUL cannot be delivered by an HTTP client at all — `undici` refuses to put them in a
 * header value — so these four cases are written straight onto a socket.
 *
 * What they establish is which layer holds the property, which matters because both layers answer
 * 400. A value carrying a bare CR, a bare LF or a NUL is refused by Node's HTTP parser before the
 * application sees the request, so the guard's own refusal code is ABSENT. A well-formed CRLF is
 * not injection into a value at all: it terminates the field and starts a real second header, so
 * the routing value arrives plain and is correctly accepted.
 */
describe('control characters in a routing header, written straight onto the socket', () => {
  interface RawResult {
    readonly status: number;
    readonly raw: string;
  }

  async function rawRequest(headerLine: string): Promise<RawResult> {
    const { port } = new URL(server.origin);
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });

    const raw = await new Promise<string>((resolve) => {
      const socket = connect(Number(port), '127.0.0.1', () => {
        socket.write(
          `POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: ${ALLOWED_ORIGIN}\r\n` +
            `Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n` +
            `Mcp-Protocol-Version: 2026-07-28\r\nMcp-Method: tools/list\r\n` +
            `${headerLine}\r\nContent-Length: ${String(body.length)}\r\nConnection: close\r\n\r\n${body}`
        );
      });
      let out = '';
      socket.setTimeout(5000, () => {
        socket.destroy();
      });
      socket.on('data', (chunk: Buffer) => {
        out += chunk.toString('latin1');
      });
      socket.on('close', () => {
        resolve(out);
      });
      socket.on('error', () => {
        resolve(out);
      });
    });

    const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(raw)?.[1] ?? '0');
    return { status, raw };
  }

  /**
   * These rows pin a third party's strictness, and they fail in the safe direction. If Node's parser
   * ever became lenient about a bare LF or a control character, the value would reach the plain-form
   * guard, the guard would refuse it with 400 and its own code, the security property would STILL
   * hold — and these rows would go red on the code assertion. A red row here means the layer moved,
   * not that a refusal was lost.
   */
  const PARSER_REFUSED = [
    { label: 'a bare line feed', headerLine: 'Mcp-Name: tools/list\nX-Injected: yes' },
    { label: 'a bare carriage return', headerLine: 'Mcp-Name: tools/list\rjunk' },
    { label: 'a NUL', headerLine: `Mcp-Name: tools/li${String.fromCharCode(0)}st` },
    { label: 'a bell control character', headerLine: `Mcp-Name: tools${String.fromCharCode(7)}` },
  ] as const;

  it.each(PARSER_REFUSED)(
    'refuses $label before the application sees it',
    async ({ headerLine }) => {
      const result = await rawRequest(headerLine);

      expect(result.status, 'refused as a bad request').toBe(400);
      expect(dispatches, 'never dispatched').toBe(0);
      expect(
        server.errors.map((error) => error.message),
        'the routing guard did not refuse this, the HTTP parser did — recorded so that nobody reads this 400 as evidence about the guard'
      ).not.toContain(ROUTING_REFUSAL_CODE);
    }
  );

  it('keeps a floor under the parser-refused table', () => {
    expect(PARSER_REFUSED.length).toBeGreaterThanOrEqual(4);
  });

  /**
   * The case that is NOT a bypass, and it belongs here so that nobody later reads the rows above
   * as "CRLF is blocked" and then assumes a smuggled routing value is possible.
   */
  it('sees a plain value when a well-formed CRLF starts a genuine second header', async () => {
    const result = await rawRequest('Mcp-Name: nutrition_lookup\r\nX-Injected: yes');

    expect(
      result.status,
      'the routing value arrived as `nutrition_lookup`, which is plain, so the guard has nothing to refuse. A 400 here would mean the CR or LF had reached the value'
    ).not.toBe(400);
    expect(
      server.errors.map((error) => error.message),
      'and the guard confirms it: no routing refusal was recorded'
    ).not.toContain(ROUTING_REFUSAL_CODE);
    expect(
      result.status,
      'no credential was presented, so the next step in the order answers'
    ).toBe(401);
  });
});
