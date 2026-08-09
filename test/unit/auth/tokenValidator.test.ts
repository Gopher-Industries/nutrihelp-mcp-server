import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTokenValidator } from '../../../src/auth/tokenValidator.ts';
import {
  createTestKeyPair,
  makeToken,
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
    response.writeHead(200, { 'content-type': 'application/json' });
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

function validator() {
  return createTokenValidator({
    jwksUrl,
    expectedIssuer: MCP_EXPECTED_ISSUER,
    expectedAudience: MCP_RESOURCE_IDENTIFIER,
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

  it('rejects an unpublished key and refetches the JWKS', async () => {
    await expect(validator().validate(await token({ key: foreignKey }))).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });

    expect(jwksRequests).toBe(2);
  });

  it('rejects a token from the wrong issuer', async () => {
    await expect(
      validator().validate(await token({ iss: 'https://other-issuer.test' }))
    ).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
    });
  });

  it('rejects a token for the wrong audience', async () => {
    await expect(
      validator().validate(await token({ aud: 'https://other-service.test' }))
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
