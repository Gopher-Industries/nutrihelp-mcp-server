/**
 * Discovery on the wire: every refusal's `resource_metadata` pointer must resolve here.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Agent, request } from 'undici';
import { createTestKeyPair, makeToken, type TestKeyPair } from '../../scripts/makeToken.ts';
import { installUpstreamMock } from '../support/upstreamMock.ts';
import { protectedResourceMetadata } from '../../src/auth/metadata.ts';
import {
  closeLocalDispatcher,
  mcpRequest,
  startTestServer,
  type TestServer,
} from '../support/mcpClient.ts';
import {
  MCP_AUTH_SERVER_URL,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  SCOPES,
  USER_A,
} from '../support/testEnv.ts';

/** Reserved for the local test server, never the mocked dispatcher. */
const localAgent = new Agent({ keepAliveTimeout: 10, keepAliveMaxTimeout: 10 });

const PRIMARY_PATH = '/.well-known/oauth-protected-resource/mcp';
const ROOT_PROBE_PATH = '/.well-known/oauth-protected-resource';

let server: TestServer;
let trustedKey: TestKeyPair;
let token: string;

/** What the generator produces for this fixture. The wire must serve exactly this. */
const EXPECTED_DOCUMENT = protectedResourceMetadata({
  resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
  authorizationServers: [MCP_AUTH_SERVER_URL],
});

interface Fetched {
  readonly status: number;
  readonly contentType: string | undefined;
  readonly body: string;
}

/** `url` may be absolute (a pointer taken from a challenge) or a path on the test server. */
async function get(url: string, headers: Record<string, string> = {}): Promise<Fetched> {
  const target = url.startsWith('http') ? url : `${server.origin}${url}`;
  const response = await request(target, { method: 'GET', headers, dispatcher: localAgent });
  const body = await response.body.text();
  const contentType = response.headers['content-type'];
  return {
    status: response.statusCode,
    contentType: Array.isArray(contentType) ? contentType.join(', ') : contentType,
    body,
  };
}

/** The pointer as a client reads it: the quoted `resource_metadata` parameter of the challenge. */
function pointerFrom(challenge: string | undefined): string {
  const match = /resource_metadata="([^"]+)"/.exec(challenge ?? '');
  expect(
    match,
    `the challenge must carry a quoted resource_metadata pointer. Got: ${challenge ?? '(absent)'}`
  ).not.toBeNull();
  return match?.[1] ?? '';
}

/**
 * The pointer names the deployed host; the test server listens on an ephemeral loopback port.
 * Only the path is followable here, and the path is the half this server owns.
 */
function onTestServer(pointer: string): string {
  return `${server.origin}${new URL(pointer).pathname}`;
}

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  token = await makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: [SCOPES.nutritionRead],
    sub: USER_A,
  });
});

beforeEach(async () => {
  server = await startTestServer();
});

afterEach(async () => {
  await server.close();
});

afterAll(async () => {
  await localAgent.close();
  await closeLocalDispatcher();
});

describe('the protected resource metadata endpoint', () => {
  it('answers the primary location with the document', async () => {
    const response = await get(PRIMARY_PATH);

    expect(response.status).toBe(200);
    expect(response.contentType).toMatch(/application\/json/);
    expect(JSON.parse(response.body)).toStrictEqual(EXPECTED_DOCUMENT);
  });

  it('answers the root probe with a byte-identical document', async () => {
    const primary = await get(PRIMARY_PATH);
    const rootProbe = await get(ROOT_PROBE_PATH);

    expect(rootProbe.status).toBe(200);
    expect(
      rootProbe.body,
      'clients probe different locations and must not get different answers — a divergence here is discovered only by whichever client picked the other one'
    ).toBe(primary.body);
  });

  it('names the authorization server the connect flow starts against', async () => {
    const document = JSON.parse((await get(PRIMARY_PATH)).body) as {
      authorization_servers: string[];
    };

    expect(document.authorization_servers).toContain(MCP_AUTH_SERVER_URL);
  });

  it('serves it without a credential, which is the only way a client could use it', async () => {
    const response = await get(PRIMARY_PATH);

    expect(
      response.status,
      'a client fetches this precisely because it does not have a token yet. Requiring one would make discovery unreachable'
    ).toBe(200);
  });

  /** Not Origin-guarded — public read, side-effect-free. Both paths checked. */
  it.each(
    [PRIMARY_PATH, ROOT_PROBE_PATH].flatMap((path) =>
      ['https://evil.example', 'null'].map((origin) => [path, origin] as const)
    )
  )(
    'answers %s with Origin %s, which the transport endpoint would refuse',
    async (path, origin) => {
      const response = await get(path, { origin });

      expect(response.status).toBe(200);
    }
  );

  it('404s a well-known path it does not publish', async () => {
    const response = await get('/.well-known/oauth-authorization-server');

    expect(
      response.status,
      "control: the authorization-server document is the backend's, and without this the 200s above could come from a server answering everything"
    ).toBe(404);
  });
});

describe('the pointer every refusal advertises', () => {
  it('resolves on this server when no credential was presented', async () => {
    const refusal = await mcpRequest(server, { method: 'tools/list' });
    expect(refusal.status).toBe(401);

    const fetched = await get(onTestServer(pointerFrom(refusal.challenge)));

    expect(
      fetched.status,
      'the 401 tells a client where to look. A 404 there is the difference between "authenticate, here is how" and a dead end'
    ).toBe(200);
    expect((JSON.parse(fetched.body) as { resource: string }).resource).toBe(
      MCP_RESOURCE_IDENTIFIER
    );
  });

  it('resolves on this server when the credential was rejected', async () => {
    const refusal = await mcpRequest(server, {
      method: 'tools/list',
      authorizationHeader: 'Bearer not-a-token',
    });
    expect(refusal.status).toBe(401);

    const fetched = await get(onTestServer(pointerFrom(refusal.challenge)));

    expect(fetched.status).toBe(200);
  });

  /** 403 uses a different challenge builder; needs injected resolver until scope map exists. */
  it('resolves on this server when the scope was insufficient', async () => {
    await server.close();
    installUpstreamMock([trustedKey]);
    server = await startTestServer({ missingScopeFor: () => SCOPES.meallogWrite });

    const refusal = await mcpRequest(server, {
      method: 'tools/call',
      name: 'record_meal',
      params: { name: 'record_meal', arguments: {} },
      token,
    });
    expect(
      refusal.status,
      `insufficient scope is 403, never 401. Got ${String(refusal.status)}`
    ).toBe(403);

    const fetched = await get(onTestServer(pointerFrom(refusal.challenge)));

    expect(
      fetched.status,
      'a 403 tells a client to seek a broader grant and points at the document naming where. A 404 there strands step-up exactly as a dead 401 pointer strands the connect flow'
    ).toBe(200);
    expect(JSON.parse(fetched.body)).toStrictEqual(EXPECTED_DOCUMENT);
  });

  it('points at a document whose resource is the audience tokens are minted for', async () => {
    const refusal = await mcpRequest(server, { method: 'tools/list' });
    const pointer = pointerFrom(refusal.challenge);
    const document = JSON.parse((await get(onTestServer(pointer))).body) as { resource: string };

    expect(document.resource).toBe(MCP_RESOURCE_IDENTIFIER);
  });
});
