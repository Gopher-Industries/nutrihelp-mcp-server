import { createRemoteJWKSet, errors, jwtVerify, type JWTPayload, type RemoteJWKSet } from 'jose';

/** Ticket 27 pins one asymmetric signing algorithm. */
export const ACCEPTED_SIGNING_ALGORITHM = 'RS256';

/** The claim that distinguishes an MCP access token from other NutriHelp tokens. */
export const MCP_ACCESS_TOKEN_TYPE = 'mcp_access';

/** A published key is reused for at most ten minutes before it must be fetched again. */
export const JWKS_CACHE_MAX_AGE_MS = 10 * 60 * 1000;

export interface TokenValidatorOptions {
  readonly jwksUrl: URL;
  readonly expectedIssuer: string;
  readonly expectedAudience: string;
}

export interface TokenValidator {
  validate(token: string): Promise<JWTPayload>;
}

export function createTokenValidator(options: TokenValidatorOptions): TokenValidator {
  const jwks: RemoteJWKSet = createRemoteJWKSet(options.jwksUrl, {
    cacheMaxAge: JWKS_CACHE_MAX_AGE_MS,
  });

  async function verify(token: string): Promise<JWTPayload> {
    const { payload } = await jwtVerify(token, jwks, {
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
    async validate(token: string): Promise<JWTPayload> {
      try {
        return await verify(token);
      } catch (error) {
        if (error instanceof errors.JWKSNoMatchingKey) {
          await jwks.reload();
          return verify(token);
        }
        throw error;
      }
    },
  };
}
