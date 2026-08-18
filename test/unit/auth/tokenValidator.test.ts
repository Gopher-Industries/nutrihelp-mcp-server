import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ACCEPTED_SIGNING_ALGORITHM,
  createTokenValidator,
  MCP_ACCESS_TOKEN_TYPE,
  type TokenValidatorOptions,
} from '../../../src/auth/tokenValidator.ts';
import {
  createTestKeyPair,
  makeToken,
  PLATFORM_ACCESS_TOKEN_TYPE,
  toJwks,
  type TestKeyPair,
} from '../../../scripts/makeToken.ts';
import { ALL_SCOPES, MCP_EXPECTED_ISSUER, MCP_RESOURCE_IDENTIFIER } from '../../support/testEnv.ts';

let trustedKey: TestKeyPair;
let foreignKey: TestKeyPair;
let server: Server;
let jwksUrl: URL;
let jwksRequests: number;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('trusted-key');
  foreignKey = await createTestKeyPair('foreign-key');

  server = createServer((_request, response) => {
    jwksRequests += 1;
    response.writeHead(200, {
      'content-type': 'application/json',
    });
    response.end(JSON.stringify(toJwks([trustedKey])));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const address = server.address() as AddressInfo;
  jwksUrl = new URL(`http://127.0.0.1:${String(address.port)}/jwks.json`);
});

beforeEach(() => {
  jwksRequests = 0;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve();
        return;
      }

      reject(error);
    });
  });
});

const TEST_JWKS_CACHE_MAX_AGE_MS = 300_000;
const TEST_REQUEST_DEADLINE_MS = 30_000;

function validator(overrides: Partial<TokenValidatorOptions> = {}) {
  return createTokenValidator({
    jwksUrl,
    expectedIssuer: MCP_EXPECTED_ISSUER,
    expectedAudience: MCP_RESOURCE_IDENTIFIER,
    cacheMaxAgeMs: TEST_JWKS_CACHE_MAX_AGE_MS,
    requestDeadlineMs: TEST_REQUEST_DEADLINE_MS,
    ...overrides,
  });
}

function token(overrides: Partial<Parameters<typeof makeToken>[0]> = {}) {
  return makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    ...overrides,
  });
}

/**
 * The pins, spelled as literals on purpose.
 *
 * Everything else in this file mints its tokens from the production constants, which is right — a
 * factory that disagreed with the validator would fail every positive case for the wrong reason. But
 * it means a change to one of these values changes what is minted *and* what is checked, so the
 * whole suite stays green while the accepted credential profile silently moves. These are the cases
 * whose job is to assert the value rather than to satisfy it, so they are the ones that write it out.
 *
 * If one of these goes red, the question is whether the change was intended and reviewed, not
 * whether the test needs updating.
 */
describe('the credential profile this server accepts', () => {
  it('accepts exactly one token type, and it is not the platform one', () => {
    expect(
      MCP_ACCESS_TOKEN_TYPE,
      'the type claim is what separates an MCP access token from every other token the estate mints. Changing it is a change to what this server accepts, and it must not be possible to make it silently'
    ).toBe('mcp_access');
    expect(
      PLATFORM_ACCESS_TOKEN_TYPE,
      "and the deployed platform's own value, which the rejection cases below present and this server must refuse"
    ).toBe('access');
    expect(
      MCP_ACCESS_TOKEN_TYPE,
      'the two must stay distinct, or refusing the platform token is untestable'
    ).not.toBe(PLATFORM_ACCESS_TOKEN_TYPE);
  });

  it('pins one asymmetric signing algorithm', () => {
    expect(
      ACCEPTED_SIGNING_ALGORITHM,
      'a symmetric algorithm here would mean this server holds a signing secret and can mint what it verifies, which is the property the asymmetric choice exists to remove'
    ).toBe('RS256');
  });
});

describe('token validator', () => {
  it('accepts a valid token', async () => {
    const payload = await validator().validate(await token());

    expect(payload.sub).toBe('user-under-test');
  });

  it('rejects an expired token', async () => {
    await expect(validator().validate(await token({ exp: '-5m' }))).rejects.toMatchObject({
      code: 'ERR_JWT_EXPIRED',
    });
  });

  it('rejects a made-up token', async () => {
    await expect(validator().validate('not-a-jwt')).rejects.toMatchObject({
      code: 'ERR_JWS_INVALID',
    });
  });

  it('rejects an unpublished key without bypassing the JWKS cooldown', async () => {
    await expect(validator().validate(await token({ key: foreignKey }))).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });

    expect(jwksRequests).toBe(1);
  });

  it('rejects a token from the wrong issuer', async () => {
    await expect(
      validator().validate(
        await token({
          iss: 'https://other-issuer.test',
        })
      )
    ).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
    });
  });

  it('rejects a token for the wrong audience', async () => {
    await expect(
      validator().validate(
        await token({
          aud: 'https://other-service.test',
        })
      )
    ).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
    });
  });

  it('rejects a token with the wrong type', async () => {
    await expect(
      validator().validate(
        await token({
          type: PLATFORM_ACCESS_TOKEN_TYPE,
        })
      )
    ).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
    });
  });

  it('rejects a token with a missing required field', async () => {
    const incompleteToken = await new SignJWT({})
      .setProtectedHeader({
        alg: 'RS256',
        kid: trustedKey.kid,
      })
      .setIssuer(MCP_EXPECTED_ISSUER)
      .setAudience(MCP_RESOURCE_IDENTIFIER)
      .setSubject('user-under-test')
      .setExpirationTime('5m')
      .sign(trustedKey.privateKey);

    await expect(validator().validate(incompleteToken)).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
    });
  });
});
