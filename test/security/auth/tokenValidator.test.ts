/**
 * Security suite: inbound token rejection. Ticket 33 cases 1 to 4.
 *
 * Asserts the wire response, never an error class — `src/errors.ts` is blocked on ticket 55.
 *
 * PASSES BECAUSE: ticket 27 landed `src/auth/tokenValidator.ts`, and ticket 65 landed
 * `src/auth/challenge.ts` plus the wiring that puts both ahead of dispatch. The split matters
 * when reading a failure here: a rejection that never happens is 27's module, and a rejection
 * that happens without a challenge, or after introspection, is 65's wiring.
 *
 * **The "no introspection request was made" assertions below are trivially true today** and cannot
 * fail: no module in the tree introspects, so the count is zero whatever the transport does. They
 * become real when ticket 59 lands `src/auth/revocation.ts` and the wiring puts a live
 * introspection call between offline validation and the scope check — at which point "the token was
 * refused before the grant was consulted" is a property with two possible answers. Until then, read
 * a green run here as saying nothing about ordering against introspection.
 */

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
} from '../../support/mcpClient.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import { expectUnauthorizedChallenge } from '../../support/assertions.ts';
import {
  ALL_SCOPES,
  CLIENT_ID,
  GRANT_A,
  INTROSPECTION_PATH,
  MCP_EXPECTED_ISSUER,
  MCP_RESOURCE_IDENTIFIER,
  USER_A,
} from '../../support/testEnv.ts';

/** Published in the in-test JWKS. The only key the server should ever trust. */
let trustedKey: TestKeyPair;
/** Never published. Signing with it is what "issued by someone else" means. */
let foreignKey: TestKeyPair;
/** The deployed platform's HS256 secret, generated per run. */
let platformSecret: Uint8Array;

let server: TestServer;
let upstream: UpstreamMock;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('mcp-signing-key-1');
  foreignKey = await createTestKeyPair('some-other-issuer-key');
  platformSecret = new Uint8Array(32);
  crypto.getRandomValues(platformSecret);
});

beforeEach(async () => {
  upstream = installUpstreamMock([trustedKey]);
  // Grant is healthy here, so every rejection below is attributable to the token itself.
  upstream.introspect({
    active: true,
    scope: ALL_SCOPES.join(' '),
    sub: USER_A,
    client_id: CLIENT_ID,
    grant_id: GRANT_A,
  });
  server = await startTestServer();
});

afterEach(async () => {
  await server.close();
  await upstream.restore();
});

afterAll(async () => {
  await closeLocalDispatcher();
});

describe('inbound token rejection at /mcp', () => {
  /**
   * CASE 1. Token issued by someone else, refused. Two shapes: a foreign authorization server,
   * and the platform's own HS256 token, which thousands of live sessions already hold.
   */
  it('refuses a token issued by a different authorization server', async () => {
    const foreignIssuerToken = await makeToken({
      key: foreignKey,
      iss: 'https://someone-elses-auth.test',
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: ALL_SCOPES,
      sub: USER_A,
    });

    expectUnauthorizedChallenge(
      await listTools(server, foreignIssuerToken),
      'case 1a: RS256 token from a foreign issuer, signed by a key absent from the JWKS'
    );

    const platformToken = await makePlatformToken({ secret: platformSecret, userId: USER_A });

    expectUnauthorizedChallenge(
      await listTools(server, platformToken),
      'case 1b: a deployed platform HS256 token presented to the MCP verifier'
    );

    // Ordering: an always-introspecting implementation passes the assertions above.
    expect(
      upstream.callsTo(INTROSPECTION_PATH),
      'case 1: refused offline, before live grant introspection'
    ).toHaveLength(0);
  });

  /**
   * CASE 2. Token meant for a different service, refused. Everything correct except `aud`. */
  it('refuses a token whose audience names a different resource', async () => {
    const wrongAudience = await makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: 'https://api.nutrihelp.test/some-other-resource',
      scopes: ALL_SCOPES,
      sub: USER_A,
    });

    expectUnauthorizedChallenge(
      await listTools(server, wrongAudience),
      'case 2: valid signature and issuer, audience names another resource'
    );

    // Ordering: offline validation precedes live introspection.
    expect(
      upstream.callsTo(INTROSPECTION_PATH),
      'case 2: refused offline, before live grant introspection'
    ).toHaveLength(0);
  });

  /** CASE 3. Expired token, refused. Caught offline, before any network call. */
  it('refuses an expired token', async () => {
    const expired = await makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: ALL_SCOPES,
      sub: USER_A,
      exp: '-5m',
    });

    expectUnauthorizedChallenge(await listTools(server, expired), 'case 3: exp is in the past');

    // Ordering: offline validation precedes live introspection.
    expect(
      upstream.callsTo(INTROSPECTION_PATH),
      'case 3: an expired token is refused offline, before live grant introspection'
    ).toHaveLength(0);
  });

  /**
   * CASE 4. Made-up token, refused. A genuine token with its signature flipped — so it reaches
   * the signature check, not the parser — plus an opaque non-JWT and a missing header.
   */
  it('refuses a forged token and an opaque non-token', async () => {
    const genuine = await makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: ALL_SCOPES,
      sub: USER_A,
    });

    expectUnauthorizedChallenge(
      await listTools(server, corruptSignature(genuine)),
      'case 4a: valid header and payload, invalid signature'
    );

    expectUnauthorizedChallenge(
      await listTools(server, 'this-is-not-a-token-at-all'),
      'case 4b: opaque bearer value that is not a JWT'
    );

    // The baseline the other cases depend on: no header at all is the same 401 and challenge.
    expectUnauthorizedChallenge(await listTools(server), 'case 4c: no Authorization header');

    // Ordering: none of these ever reaches live introspection.
    expect(
      upstream.callsTo(INTROSPECTION_PATH),
      'case 4: an unverifiable token is refused offline, before live grant introspection'
    ).toHaveLength(0);
  });

  /**
   * Type confusion, not one of the ten cases. Without the type pin, ANY token the issuer
   * mints is an MCP token.
   */
  it('refuses a token whose type claim is not the MCP access type', async () => {
    const wrongType = await makeToken({
      key: trustedKey,
      iss: MCP_EXPECTED_ISSUER,
      aud: MCP_RESOURCE_IDENTIFIER,
      scopes: ALL_SCOPES,
      sub: USER_A,
      type: PLATFORM_ACCESS_TOKEN_TYPE,
    });

    expectUnauthorizedChallenge(
      await listTools(server, wrongType),
      'wrong type: right key, issuer, audience and expiry, but not an MCP access token'
    );

    expect(
      upstream.callsTo(INTROSPECTION_PATH),
      'wrong type: refused offline, before live grant introspection'
    ).toHaveLength(0);
  });
});
