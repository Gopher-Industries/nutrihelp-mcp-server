import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { errors } from 'jose';
import {
  ACCEPTED_SIGNING_ALGORITHM,
  createTokenValidator,
  KeySetUnavailableError,
  type KeySetFailure,
  MCP_ACCESS_TOKEN_TYPE,
  type TokenValidatorOptions,
} from '../../../src/auth/tokenValidator.ts';
import {
  createTestKeyPair,
  makeToken,
  PLATFORM_ACCESS_TOKEN_TYPE,
  type TestKeyPair,
} from '../../../scripts/makeToken.ts';
import { installUpstreamMock, type UpstreamMock } from '../../support/upstreamMock.ts';
import {
  ALL_SCOPES,
  MCP_EXPECTED_ISSUER,
  MCP_JWKS_URL,
  MCP_RESOURCE_IDENTIFIER,
} from '../../support/testEnv.ts';

const JWKS_PATH = new URL(MCP_JWKS_URL).pathname;

const TEST_JWKS_CACHE_MAX_AGE_MS = 300_000;
const TEST_REQUEST_DEADLINE_MS = 30_000;

/** jose's unknown-key refetch cooldown — not configured by this server. */
const JWKS_REFETCH_COOLDOWN_MS = 30_000;

let trustedKey: TestKeyPair;
let rotatedKey: TestKeyPair;
let foreignKey: TestKeyPair;
let upstream: UpstreamMock;

beforeAll(async () => {
  trustedKey = await createTestKeyPair('trusted-key');
  rotatedKey = await createTestKeyPair('rotated-key');
  foreignKey = await createTestKeyPair('foreign-key');
});

beforeEach(() => {
  upstream = installUpstreamMock([trustedKey]);
});

afterEach(async () => {
  vi.useRealTimers();
  await upstream.restore();
});

/** Key-set requests that actually left, rather than a counter the fixture increments for itself. */
function jwksRequests(): number {
  return upstream.callsTo(JWKS_PATH).length;
}

function validator(overrides: Partial<TokenValidatorOptions> = {}) {
  return createTokenValidator({
    jwksUrl: new URL(MCP_JWKS_URL),
    expectedIssuer: MCP_EXPECTED_ISSUER,
    expectedAudience: MCP_RESOURCE_IDENTIFIER,
    cacheMaxAgeMs: TEST_JWKS_CACHE_MAX_AGE_MS,
    requestDeadlineMs: TEST_REQUEST_DEADLINE_MS,
    ...overrides,
  });
}

/** All tokens minted through the shared factory; overrides pin the field under test. */
function token(overrides: Partial<Parameters<typeof makeToken>[0]> = {}) {
  return makeToken({
    key: trustedKey,
    iss: MCP_EXPECTED_ISSUER,
    aud: MCP_RESOURCE_IDENTIFIER,
    scopes: ALL_SCOPES,
    ...overrides,
  });
}

/** Five minutes out, in epoch seconds — the shape a raw `exp` claim actually takes. */
const PLAUSIBLE_EXPIRY = Math.floor(Date.now() / 1000) + 300;

/** One row per claim guarded by assertNoOmissionConflict; messages spelled out, not templated. */
const OMISSION_CONFLICTS: readonly {
  readonly claim: string;
  readonly overrides: Partial<Parameters<typeof makeToken>[0]>;
  readonly message: string;
}[] = [
  {
    claim: 'iss',
    overrides: { iss: null, claims: { iss: MCP_EXPECTED_ISSUER } },
    message: 'makeToken: cannot omit iss while also supplying it through claims',
  },
  {
    claim: 'aud',
    overrides: { aud: null, claims: { aud: MCP_RESOURCE_IDENTIFIER } },
    message: 'makeToken: cannot omit aud while also supplying it through claims',
  },
  {
    claim: 'type',
    overrides: { type: null, claims: { type: MCP_ACCESS_TOKEN_TYPE } },
    message: 'makeToken: cannot omit type while also supplying it through claims',
  },
  {
    claim: 'exp',
    overrides: { exp: null, claims: { exp: PLAUSIBLE_EXPIRY } },
    message: 'makeToken: cannot omit exp while also supplying it through claims',
  },
];

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

  /** jose evaluates expiry only when the claim is present; `requiredClaims` catches the absence. */
  it('rejects a token minted with no expiry claim', async () => {
    await expect(validator().validate(await token({ exp: null }))).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'exp',
      reason: 'missing',
    });
  });

  it('guards every claim the factory guards, and the table cannot quietly shrink', () => {
    expect(OMISSION_CONFLICTS.map((row) => row.claim)).toEqual(['iss', 'aud', 'type', 'exp']);
  });

  it.each(OMISSION_CONFLICTS)(
    'refuses a contradictory $claim omission at mint time',
    async ({ overrides, message }) => {
      await expect(token(overrides)).rejects.toThrow(new Error(message));
    }
  );

  it('rejects a made-up token', async () => {
    await expect(validator().validate('not-a-jwt')).rejects.toMatchObject({
      code: 'ERR_JWS_INVALID',
    });
  });

  it('rejects an unpublished key without bypassing the JWKS cooldown', async () => {
    await expect(validator().validate(await token({ key: foreignKey }))).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });

    expect(
      jwksRequests(),
      'the initial fetch, and no second one chasing the unknown identifier: a rejected credential must not be able to buy an extra outbound request'
    ).toBe(1);
  });

  it('refetches for an unknown key identifier once the cooldown elapses, and not again inside it', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });

    // Cache lifetime refetch is not cooldown-gated; keep the advance inside the lifetime.
    expect(TEST_JWKS_CACHE_MAX_AGE_MS).toBeGreaterThan(JWKS_REFETCH_COOLDOWN_MS + 1_000);

    const check = validator();

    await check.validate(await token());
    expect(
      jwksRequests(),
      'the first verification populates the cache, or the rotation below has nothing to invalidate'
    ).toBe(1);

    upstream.publishKeys([trustedKey, rotatedKey]);

    vi.setSystemTime(Date.now() + JWKS_REFETCH_COOLDOWN_MS + 1_000);

    const payload = await check.validate(await token({ key: rotatedKey }));

    expect(
      payload.sub,
      'the newly published key verifies, so the validator went back for the set rather than serving the identifier it had cached at startup'
    ).toBe('user-under-test');
    expect(
      jwksRequests(),
      'and it went back exactly once. A validator holding a stale set would read one here and reject a legitimately rotated key until the process restarted'
    ).toBe(2);

    // The bound, measured from the refetch that just happened rather than from startup.
    await expect(check.validate(await token({ key: foreignKey }))).rejects.toMatchObject({
      code: 'ERR_JWKS_NO_MATCHING_KEY',
    });

    expect(
      jwksRequests(),
      'a further unknown identifier inside the fresh cooldown is refused from cache. Without this, every unverifiable token an unauthenticated caller sends becomes an outbound request to the authorization server'
    ).toBe(2);
  });

  /** Same error code for every claim rejection — assert `claim`/`reason`, not code alone. */
  it('rejects a token from the wrong issuer', async () => {
    await expect(
      validator().validate(
        await token({
          iss: 'https://other-issuer.test',
        })
      )
    ).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'iss',
      reason: 'check_failed',
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
      claim: 'aud',
      reason: 'check_failed',
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
      claim: 'type',
      reason: 'mismatch',
    });
  });

  it('rejects a token minted with no issuer claim', async () => {
    await expect(validator().validate(await token({ iss: null }))).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'iss',
      reason: 'missing',
    });
  });

  it('rejects a token minted with no audience claim', async () => {
    await expect(validator().validate(await token({ aud: null }))).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'aud',
      reason: 'missing',
    });
  });

  it('rejects a token minted with no type claim', async () => {
    // Absent rather than wrong: a present-but-unexpected value is the type case above, and the
    // two must not be able to stand in for each other.
    await expect(validator().validate(await token({ type: null }))).rejects.toMatchObject({
      code: 'ERR_JWT_CLAIM_VALIDATION_FAILED',
      claim: 'type',
      reason: 'missing',
    });
  });
});

/**
 * Class comment says no `cause`; nothing asserted it. Defence in depth — jose attaches payload
 * in `validateClaimsSet`, after key resolution, so no payload-bearing error reaches this throw
 * today. Both arms driven: a cause-forwarding refactor would most naturally hit only one.
 */
describe('the key-set failure carries no cause', () => {
  const unusable = new errors.JWKSInvalid('the key set was not a key set');
  // Second unreachable row is load-bearing: contract is "not JOSEError", not "is TypeError".
  // TypeError alone leaves `instanceof TypeError ? unreachable : unusable` green on both rows.
  const unreachable = new TypeError('fetch failed');
  const alsoUnreachable = new Error('a failure that is neither a jose error nor a TypeError');

  it.each([
    ['unusable', 'a jose error', unusable],
    ['unreachable', 'a TypeError', unreachable],
    ['unreachable', 'neither jose nor TypeError', alsoUnreachable],
  ] as readonly (readonly [KeySetFailure, string, Error])[])(
    'drops the cause on the %s arm, given %s',
    async (failure, _thrownDescription, thrown) => {
      const validate = validator({
        keySetFetch: () => Promise.reject(thrown),
      });

      const raised = await validate.validate(await token()).then(
        () => undefined,
        (error: unknown) => error
      );

      expect(raised).toBeInstanceOf(KeySetUnavailableError);
      const keySetError = raised as KeySetUnavailableError;
      expect(keySetError.failure).toBe(failure);
      expect(keySetError.cause).toBeUndefined();
      expect(Object.prototype.hasOwnProperty.call(keySetError, 'cause')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(keySetError, 'payload')).toBe(false);
    }
  );
});
