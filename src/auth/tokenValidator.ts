import {
  createRemoteJWKSet,
  customFetch,
  errors,
  jwtVerify,
  type FetchImplementation,
  type JWTPayload,
  type JWTVerifyGetKey,
  type RemoteJWKSet,
} from 'jose';
import { getWithoutCredential } from '../upstream/client.ts';

export const ACCEPTED_SIGNING_ALGORITHM = 'RS256';

/** Distinguishes an MCP access token from other NutriHelp tokens. */
export const MCP_ACCESS_TOKEN_TYPE = 'mcp_access';

/** Injected so tests can substitute a fetcher without mocking this module. */
export type KeySetFetch = FetchImplementation;

export interface TokenValidatorOptions {
  readonly jwksUrl: URL;
  readonly expectedIssuer: string;
  readonly expectedAudience: string;
  /** Cache lifetime in ms. Required so jose's own default cannot sneak back in. */
  readonly cacheMaxAgeMs: number;
  /** Remaining budget for the whole MCP request, in ms. jose's timeout is not used. */
  readonly requestDeadlineMs: number;
  /**
   * Omit in production: the fallback is `getWithoutCredential`. Optional only because that
   * default is module-private. Passing a fetcher that dials out itself reopens a second door.
   */
  readonly keySetFetch?: KeySetFetch;
}

export interface TokenValidator {
  validate(token: string): Promise<JWTPayload>;
}

/** `unusable`: endpoint answered badly. `unreachable`: bytes never arrived. */
export type KeySetFailure = 'unusable' | 'unreachable';

/**
 * Key set could not be consulted, so nothing is known about the presented credential.
 * Raised at retrieval so the transport classifies structurally.
 * No `cause`: jose hangs a decoded token payload on the error and on `error.cause`.
 */
export class KeySetUnavailableError extends Error {
  readonly failure: KeySetFailure;

  constructor(failure: KeySetFailure) {
    super(`the key set was ${failure}`);
    this.name = 'KeySetUnavailableError';
    this.failure = failure;
  }
}

/**
 * Resolver errors about the token, not the key set. `JOSENotSupported` is listed because jose
 * can raise it for a symmetric/unknown key alg; today the alg pin runs first, but if that order
 * changes this must still be a refused token, not an outage.
 */
function isAboutTheToken(cause: unknown): boolean {
  return (
    cause instanceof errors.JWKSNoMatchingKey ||
    cause instanceof errors.JWKSMultipleMatchingKeys ||
    cause instanceof errors.JOSENotSupported
  );
}

/**
 * Default fetch: the one module allowed to call out.
 * Spends the whole request budget because JWKS is currently the only stage. Do not copy this
 * for introspection/exchange/audit — split remaining time instead. Do not forward jose's
 * AbortSignal: that reinstates its 5s default.
 */
function keySetFetchThroughTheOneDoor(deadlineMs: number): KeySetFetch {
  return async (url, requested) =>
    getWithoutCredential({
      url,
      headers: requested.headers,
      redirect: requested.redirect,
      deadlineMs,
      // Transport does not thread a correlation id yet; the door mints one that does not join.
      correlationId: undefined,
    });
}

export function createTokenValidator(options: TokenValidatorOptions): TokenValidator {
  const jwks: RemoteJWKSet = createRemoteJWKSet(options.jwksUrl, {
    // Must be the symbol. `{ customFetch: fn }` typechecks, is ignored, and jose uses its own fetch.
    [customFetch]: options.keySetFetch ?? keySetFetchThroughTheOneDoor(options.requestDeadlineMs),
    cacheMaxAge: options.cacheMaxAgeMs,
    // jose's 30s cooldown is inherited on purpose: it bounds unknown-kid refetch. Not ours
    // to configure until key rotation owns it.
  });

  const resolveKey: JWTVerifyGetKey = async (protectedHeader, input) => {
    try {
      return await jwks(protectedHeader, input);
    } catch (cause: unknown) {
      if (isAboutTheToken(cause)) {
        throw cause;
      }
      // JOSEError = endpoint answered unusably. Anything else = bytes never arrived.
      // Do not key off TypeError: the door currently lets fetch's through, and that changes
      // the moment it grows its own error class.
      throw new KeySetUnavailableError(
        cause instanceof errors.JOSEError ? 'unusable' : 'unreachable'
      );
    }
  };

  async function verify(token: string): Promise<JWTPayload> {
    const { payload } = await jwtVerify(token, resolveKey, {
      algorithms: [ACCEPTED_SIGNING_ALGORITHM],
      issuer: options.expectedIssuer,
      audience: options.expectedAudience,
      requiredClaims: ['type'],
    });

    if (payload.type !== MCP_ACCESS_TOKEN_TYPE) {
      throw new errors.JWTClaimValidationFailed(
        'unexpected "type" claim value',
        payload,
        'type',
        'mismatch'
      );
    }

    return payload;
  }

  return {
    validate: verify,
  };
}
