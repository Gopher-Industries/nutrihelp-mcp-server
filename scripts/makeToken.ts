/**
 * Test-key factory. Lives in `scripts/` so it does not ship in `dist/`.
 * Never hand-write a JWT string. Sets the `type` claim only — no JOSE header `typ` is pinned.
 */

import { SignJWT, exportJWK, generateKeyPair, type JWK } from 'jose';
import { MCP_ACCESS_TOKEN_TYPE } from '../src/auth/tokenValidator.ts';

/** jose returns platform `CryptoKey`s; derive rather than import a name. */
type GeneratedKeyPair = Awaited<ReturnType<typeof generateKeyPair>>;
type PrivateKey = GeneratedKeyPair['privateKey'];

export const MCP_TOKEN_ALG = 'RS256';

/** Imported so minted tokens match the validator. The unit test spells the literal to pin the value. */
export { MCP_ACCESS_TOKEN_TYPE };

/** The `type` claim on the deployed platform HS256 token. */
export const PLATFORM_ACCESS_TOKEN_TYPE = 'access';

export interface TestKeyPair {
  readonly kid: string;
  readonly alg: string;
  readonly privateKey: PrivateKey;
  readonly publicJwk: JWK;
}

/** Generate an RS256 keypair. Per suite, never at module scope in a production path. */
export async function createTestKeyPair(kid: string, alg = MCP_TOKEN_ALG): Promise<TestKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const jwk = await exportJWK(publicKey);
  return {
    kid,
    alg,
    privateKey,
    publicJwk: { ...jwk, kid, alg, use: 'sig' },
  };
}

/** JWKS document from test keys. Served from an in-test intercept, never over the network. */
export function toJwks(keys: readonly TestKeyPair[]): { keys: JWK[] } {
  return { keys: keys.map((key) => key.publicJwk) };
}

export interface MakeTokenOptions {
  /** The key that signs. A key absent from the served JWKS is how "issued by someone else" is expressed. */
  readonly key: TestKeyPair;
  readonly iss: string;
  readonly aud: string;
  readonly scopes: readonly string[];
  /** NutriHelp `users.user_id`. */
  readonly sub?: string;
  /** Absolute epoch seconds, a jose relative string such as `'-5m'`, or `null` to omit. Defaults to `'5m'`. */
  readonly exp?: number | string | null;
  /** Overrides the header `kid`, for the unknown-key-identifier cases. */
  readonly kid?: string;
  readonly clientId?: string;
  readonly grantId?: string;
  readonly jti?: string;
  /** The `type` claim. Defaults to `mcp_access`. */
  readonly type?: string;
  readonly claims?: Readonly<Record<string, unknown>>;
}

/** Mint an MCP access token. Every negative case is one field of this object. */
export async function makeToken(options: MakeTokenOptions): Promise<string> {
  const {
    key,
    iss,
    aud,
    scopes,
    sub = 'user-under-test',
    exp = '5m',
    kid = key.kid,
    clientId = 'https://client.test/mcp-client.json',
    grantId = 'grant-under-test',
    jti = `jti-${String(Math.random()).slice(2)}`,
    type = MCP_ACCESS_TOKEN_TYPE,
    claims = {},
  } = options;

  const unsigned = new SignJWT({
    scope: scopes.join(' '),
    client_id: clientId,
    grant_id: grantId,
    type,
    ...claims,
  })
    .setProtectedHeader({ alg: key.alg, kid })
    .setIssuer(iss)
    .setAudience(aud)
    .setSubject(sub)
    .setJti(jti)
    .setIssuedAt();

  return (exp === null ? unsigned : unsigned.setExpirationTime(exp)).sign(key.privateKey);
}

export interface MakePlatformTokenOptions {
  /** The platform HS256 secret. Generated per test; never a committed value. */
  readonly secret: Uint8Array;
  readonly userId: string;
  readonly email?: string;
  readonly role?: string;
  readonly exp?: number | string;
}

/** The deployed platform's HS256 profile, so the MCP verifier can be proven to refuse it. */
export async function makePlatformToken(options: MakePlatformTokenOptions): Promise<string> {
  const { secret, userId, email = 'someone@nutrihelp.test', role = 'user', exp = '5m' } = options;

  return new SignJWT({
    userId,
    email,
    role,
    type: PLATFORM_ACCESS_TOKEN_TYPE,
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(secret);
}

/**
 * Invalidate a real token's signature, leaving header and payload intact — so the request
 * reaches the signature check instead of dying in the parser.
 */
export function corruptSignature(token: string): string {
  const parts = token.split('.');
  const signature = parts[2];
  if (parts.length !== 3 || signature === undefined || signature.length === 0) {
    throw new Error('corruptSignature expects a three-part compact JWS');
  }
  const flipped = signature.startsWith('A') ? `B${signature.slice(1)}` : `A${signature.slice(1)}`;
  return `${parts[0] ?? ''}.${parts[1] ?? ''}.${flipped}`;
}
