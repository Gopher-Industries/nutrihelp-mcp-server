/**
 * Served JWKS is derived from the signing key, never a field off disk.
 * Private-member alarm in `derivePublicJwk` is unreachable via the export (input is a public
 * JWK); cases below pin the property a private-JWK stub would break.
 * Entrypoint: import must not issue, and a direct run must — a permanently-false guard would
 * pass the import case and silent-no-op `token:test`.
 */

import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decodeProtectedHeader, exportJWK, importJWK, jwtVerify, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { derivePublicJwk } from '../../scripts/issueTestToken.ts';
import {
  createTestKeyPair,
  makeToken,
  MCP_TOKEN_ALG,
  type TestKeyPair,
} from '../../scripts/makeToken.ts';

/** Allowed public RSA JWK members. Hand-written: deriving from the subject cannot falsify it. */
const PUBLIC_RSA_MEMBERS: readonly string[] = ['kty', 'n', 'e'];

/** Public RSA members plus kid/alg/use. Anything else was not meant to be served. */
const PUBLISHABLE_MEMBERS: readonly string[] = [...PUBLIC_RSA_MEMBERS, 'kid', 'alg', 'use'];

/** Deliberately different, so a `kid` that came from anywhere but the argument is visible. */
const PAIR_KID = 'key-pair-own-kid';
const SERVED_KID = 'served-key-set-kid';

const ISSUER = 'https://issuer.test';
const AUDIENCE = 'https://resource.test/mcp';
const SUBJECT = 'local-dev-user-under-test';

/**
 * Private-only members: subtract the test's public list, never the derived JWK's keys
 * (that would make every absence assertion true by construction).
 */
function privateOnlyMembers(privateJwk: JWK): readonly string[] {
  return Object.keys(privateJwk).filter((member) => !PUBLIC_RSA_MEMBERS.includes(member));
}

/** Derived rather than named: the platform key type is a value here, not a type. */
type VerificationKey = Exclude<Awaited<ReturnType<typeof importJWK>>, Uint8Array>;

/** jose hands back an asymmetric key or a symmetric one; only the first can verify RS256. */
async function asVerificationKey(jwk: JWK): Promise<VerificationKey> {
  const key = await importJWK(jwk, MCP_TOKEN_ALG);
  if (key instanceof Uint8Array) {
    throw new Error('the published key set imported as a symmetric key, which cannot verify RS256');
  }
  return key;
}

let pair: TestKeyPair;
let derived: JWK;
let privateJwk: JWK;

beforeAll(async () => {
  pair = await createTestKeyPair(PAIR_KID, MCP_TOKEN_ALG);
  derived = await derivePublicJwk(pair.privateKey, SERVED_KID, MCP_TOKEN_ALG);
  privateJwk = await exportJWK(pair.privateKey);
});

describe('the published key set is derived from the key that signs', () => {
  it('publishes the RSA public parameters, so an empty object cannot satisfy the absence cases', () => {
    expect(derived.kty).toBe('RSA');
    expect(typeof derived.n).toBe('string');
    expect(derived.n).not.toBe('');
    expect(typeof derived.e).toBe('string');
    expect(derived.e).not.toBe('');
  });

  it('publishes nothing beyond the public parameters and the key identity', () => {
    const unexpected = Object.keys(derived).filter(
      (member) => !PUBLISHABLE_MEMBERS.includes(member)
    );
    expect(unexpected).toEqual([]);
  });

  it('publishes none of the members that only a private key carries', () => {
    const forbidden = privateOnlyMembers(privateJwk);

    // Non-empty and includes `d`, or the walk below can iterate nothing and still pass.
    expect(forbidden.length).toBeGreaterThan(0);
    expect(forbidden).toContain('d');

    const published = new Map<string, unknown>(Object.entries(derived));
    for (const member of forbidden) {
      expect(published.has(member)).toBe(false);
    }
  });

  it('derives the same modulus and exponent the key pair reports for its own public half', () => {
    // Factory public export vs derive-from-private: agreement is the derivation working.
    expect(derived.n).toBe(pair.publicJwk.n);
    expect(derived.e).toBe(pair.publicJwk.e);
  });
});

describe('the served key identity', () => {
  it('returns the key identifier it was given, not the one the key pair carries', () => {
    expect(derived.kid).toBe(SERVED_KID);
    expect(derived.kid).not.toBe(PAIR_KID);
  });

  it('returns the algorithm it was given', () => {
    expect(derived.alg).toBe(MCP_TOKEN_ALG);
  });

  it('marks the published key for signature verification', () => {
    expect(derived.use).toBe('sig');
  });
});

describe('the published key verifies what the issuer signs', () => {
  it('verifies a token minted with the matching private key', async () => {
    const token = await makeToken({
      key: pair,
      iss: ISSUER,
      aud: AUDIENCE,
      scopes: [],
      sub: SUBJECT,
    });

    const { payload } = await jwtVerify(token, await asVerificationKey(derived), {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    expect(payload.sub).toBe(SUBJECT);
    expect(payload.iss).toBe(ISSUER);
  });

  it('is selected by the token header, so the key set and the header cannot drift', async () => {
    const token = await makeToken({
      key: pair,
      iss: ISSUER,
      aud: AUDIENCE,
      scopes: [],
      kid: SERVED_KID,
    });

    expect(decodeProtectedHeader(token).kid).toBe(derived.kid);
    expect(decodeProtectedHeader(token).alg).toBe(derived.alg);
  });

  it('refuses a token signed by a different key', async () => {
    const other = await createTestKeyPair('some-other-key', MCP_TOKEN_ALG);
    const token = await makeToken({
      key: other,
      iss: ISSUER,
      aud: AUDIENCE,
      scopes: [],
      sub: SUBJECT,
    });

    await expect(
      jwtVerify(token, await asVerificationKey(derived), { issuer: ISSUER, audience: AUDIENCE })
    ).rejects.toThrow();
  });
});

describe('the entrypoint guard', () => {
  const ISSUER_SCRIPT = fileURLToPath(new URL('../../scripts/issueTestToken.ts', import.meta.url));

  /** Anything the issuer prints only once it has actually started issuing. */
  const ISSUER_OUTPUT = ['key set:', 'access token', 'Inspector config:'];

  const COMPLETED = 'import-completed-without-issuing';

  /** First act of `main` (missing env). Reaching it proves `main` ran; nothing is bound or written. */
  const FIRST_ACT_OF_MAIN = 'Missing required environment variable: MCP_JWKS_URL';

  /**
   * Strip MCP_* / PORT and cwd off-repo so dotenv finds no `.env`. Distinguishes whether `main`
   * ran without binding a port: `.dev/` is relative to the script, so going further would write
   * the developer's real session config.
   */
  function runIssuer(args: readonly string[]): ReturnType<typeof spawnSync> {
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !name.startsWith('MCP_') && name !== 'PORT')
    );
    return spawnSync(process.execPath, [...args], {
      cwd: tmpdir(),
      env,
      encoding: 'utf8',
      timeout: 60_000,
    });
  }

  it('runs no server, mints no token and writes no session config when imported', () => {
    // Child process: this file's static import is already cached.
    const result = runIssuer([
      '--input-type=module',
      '-e',
      `await import(${JSON.stringify(pathToFileURL(ISSUER_SCRIPT).href)});` +
        `console.log(${JSON.stringify(COMPLETED)});`,
    ]);

    expect(result.error).toBeUndefined();
    expect(result.stdout).toContain(COMPLETED);
    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain(FIRST_ACT_OF_MAIN);

    for (const line of ISSUER_OUTPUT) {
      expect(result.stdout).not.toContain(line);
    }
  });

  it('does issue when the script itself is what was run', () => {
    // Direct run must reach `main`. A permanently-false guard exits 0 having done nothing.
    const result = runIssuer([ISSUER_SCRIPT]);

    expect(result.error).toBeUndefined();
    expect(result.stderr).toContain(FIRST_ACT_OF_MAIN);
    expect(result.status).toBe(1);
    expect(result.stdout).not.toContain(COMPLETED);
  });
});
