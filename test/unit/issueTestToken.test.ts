/**
 * Served JWKS is derived from the signing key, never a field off disk.
 * Private-member alarm in `derivePublicJwk` is unreachable via the export; cases pin what a
 * private-JWK stub would break. Entrypoint: import must not issue; a direct run must.
 * Refusal to start: "nothing was changed" means nothing on disk. Driven over an isolated tree
 * because the issuer resolves `.dev/` from its own location.
 */

import { spawn, spawnSync, type ChildProcess, type SpawnSyncReturns } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decodeProtectedHeader, exportJWK, importJWK, jwtVerify, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { derivePublicJwk } from '../../scripts/issueTestToken.ts';
import {
  createTestKeyPair,
  makeToken,
  MCP_TOKEN_ALG,
  type TestKeyPair,
} from '../../scripts/makeToken.ts';
import { selfSignedCertificate } from '../support/selfSignedCert.ts';

/** Script under test. Entrypoint cases run it; isolation cases copy it. */
const ISSUER_SCRIPT = fileURLToPath(new URL('../../scripts/issueTestToken.ts', import.meta.url));

/**
 * Env minus everything the issuer reads. Scrubbed rather than overwritten: a leftover would
 * let an incomplete case pass. `.dev/` is resolved from the script, so going further writes
 * into the developer's real one.
 */
function scrubbedEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith('MCP_') && name !== 'PORT')
  );
}

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
  /** Anything the issuer prints only once it has actually started issuing. */
  const ISSUER_OUTPUT = ['key set:', 'access token', 'Inspector config:'];

  const COMPLETED = 'import-completed-without-issuing';

  /** First act of `main` (missing env). Reaching it proves `main` ran; nothing is bound or written. */
  const FIRST_ACT_OF_MAIN = 'Missing required environment variable: MCP_JWKS_URL';

  /**
   * Scrubbed env, cwd off-repo so dotenv finds no `.env`. Distinguishes whether `main` ran
   * without binding a port: `.dev/` is relative to the script.
   */
  function runIssuer(args: readonly string[]): ReturnType<typeof spawnSync> {
    return spawnSync(process.execPath, [...args], {
      cwd: tmpdir(),
      env: scrubbedEnv(),
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

describe('a run that never starts changes nothing on disk', () => {
  const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));

  /** Sentence `bind` rejects with. The promise these cases hold the issuer to. */
  const ADDRESS_IN_USE = 'is already in use, so this issuer did not start and nothing was changed';

  /** Last line of a successful run. Printed only once key and config are on disk. */
  const ISSUER_STARTED = 'Leave this running.';

  /** RS256 + TLS is slower than the default case budget. */
  const ISSUER_RUN_TIMEOUT_MS = 60_000;

  /** Issuer directory contents when nothing has run yet. */
  const SEEDED_DEV_CONTENTS: readonly string[] = ['tls-cert.pem', 'tls-key.pem'];

  interface IsolatedIssuer {
    /** Scratch root the child runs in. */
    readonly root: string;
    readonly script: string;
    readonly signingKey: string;
    readonly inspectorConfig: string;
    /** Everything in `.dev/`, sorted. Named-file-only checks miss a pre-bind write of any other path. */
    readonly contents: () => readonly string[];
  }

  const scratchRoots: string[] = [];
  const started: ChildProcess[] = [];

  /**
   * Isolated copy of the tree the issuer resolves paths against. `.dev/` is off the script's
   * location; a fresh copy starts with no signing key. `src/` is copied because `makeToken.ts`
   * imports it; the script under test stays byte-identical to what ships.
   */
  function isolatedIssuer(): IsolatedIssuer {
    const root = mkdtempSync(join(REPO_ROOT, 'test', 'TMP_issuer-'));
    scratchRoots.push(root);
    cpSync(join(REPO_ROOT, 'src'), join(root, 'src'), { recursive: true });
    cpSync(join(REPO_ROOT, 'scripts'), join(root, 'scripts'), { recursive: true });

    const dev = join(root, '.dev');
    mkdirSync(dev);
    // Generated per tree: a committed PEM pair would be a secret-shaped fixture.
    const { keyPem, certPem } = selfSignedCertificate('localhost');
    writeFileSync(join(dev, 'tls-key.pem'), keyPem);
    writeFileSync(join(dev, 'tls-cert.pem'), certPem);

    const script = join(root, 'scripts', 'issueTestToken.ts');
    expect(
      readFileSync(script, 'utf8'),
      'the isolated copy of the issuer is not byte-identical to the one that ships, so every case below is asserting over a different script'
    ).toBe(readFileSync(ISSUER_SCRIPT, 'utf8'));

    const contents = (): readonly string[] => readdirSync(dev).sort();

    // Non-vacuity for every listing below, and pins the starting state: no key on disk.
    expect(
      contents(),
      'the isolated issuer directory does not start as exactly the TLS pair, so neither the starting state nor the listing accessor is what the cases below assume'
    ).toEqual(SEEDED_DEV_CONTENTS);

    return {
      root,
      script,
      signingKey: join(dev, 'signing-key.json'),
      inspectorConfig: join(dev, 'inspector.json'),
      contents,
    };
  }

  interface HeldPort {
    readonly port: number;
    readonly release: () => Promise<void>;
  }

  /** Listener on an ephemeral port, kept open so the issuer's bind must fail. */
  function holdPort(): Promise<HeldPort> {
    return new Promise((resolve, reject) => {
      const holder: Server = createServer();
      holder.once('error', reject);
      holder.listen(0, '127.0.0.1', () => {
        const address = holder.address();
        if (address === null || typeof address === 'string') {
          reject(new Error('the port holder reported no numeric address, so no port was reserved'));
          return;
        }
        resolve({
          port: address.port,
          release: () =>
            new Promise<void>((closed) => {
              holder.close(() => {
                closed();
              });
            }),
        });
      });
    });
  }

  /** Reserve then release: the kernel hands out a port nothing else is on. */
  async function freePort(): Promise<number> {
    const holder = await holdPort();
    await holder.release();
    return holder.port;
  }

  /** The four variables the issuer reads, over a scrubbed environment. */
  function issuerEnv(port: number): NodeJS.ProcessEnv {
    const keySetOrigin = `https://127.0.0.1:${String(port)}`;
    return {
      ...scrubbedEnv(),
      MCP_JWKS_URL: `${keySetOrigin}/jwks`,
      MCP_EXPECTED_ISSUER: keySetOrigin,
      MCP_RESOURCE_IDENTIFIER: 'https://localhost:3000/mcp',
      PORT: '3000',
    };
  }

  /** String encoding: failure messages interpolate what it captured. */
  function runIssuerIn(tree: IsolatedIssuer, port: number): SpawnSyncReturns<string> {
    return spawnSync(process.execPath, [tree.script], {
      cwd: tree.root,
      env: issuerEnv(port),
      encoding: 'utf8',
      timeout: ISSUER_RUN_TIMEOUT_MS,
    });
  }

  /** Keeps serving; cannot be driven with `spawnSync`. */
  function startIssuerIn(tree: IsolatedIssuer, port: number): ChildProcess {
    const child = spawn(process.execPath, [tree.script], {
      cwd: tree.root,
      env: issuerEnv(port),
    });
    started.push(child);
    return child;
  }

  /** Resolve on `needle`; reject with everything seen so a stall is not a silent timeout. */
  function waitForOutput(child: ChildProcess, needle: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let seen = '';
      const stall = setTimeout(() => {
        reject(new Error(`the issuer never printed "${needle}". It emitted: ${seen}`));
      }, ISSUER_RUN_TIMEOUT_MS - 15_000);
      stall.unref();

      const collect = (chunk: Buffer): void => {
        seen += chunk.toString('utf8');
        if (seen.includes(needle)) {
          clearTimeout(stall);
          resolve(seen);
        }
      };
      child.stdout?.on('data', collect);
      child.stderr?.on('data', collect);
      child.once('exit', (code) => {
        clearTimeout(stall);
        // `freePort` reserves then releases; the port is free, not guaranteed. Address-in-use
        // here is that race, not an issuer defect.
        reject(
          new Error(
            `the issuer exited with ${String(code)} before it served. If what follows says the address is already in use, something took the port between reservation and start; that is a flake in this harness, not a defect in the script. It emitted: ${seen}`
          )
        );
      });
    });
  }

  function stopIssuer(child: ChildProcess): Promise<void> {
    if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
    return new Promise((stopped) => {
      child.once('close', () => {
        stopped();
      });
      child.kill();
    });
  }

  /** Shape the issuer stores, so a run takes the load path rather than create. */
  async function seedSigningKey(tree: IsolatedIssuer): Promise<string> {
    const seeded = await createTestKeyPair('key-already-on-disk', MCP_TOKEN_ALG);
    const document = {
      kid: seeded.kid,
      alg: seeded.alg,
      privateJwk: await exportJWK(seeded.privateKey),
    };
    const serialised = `${JSON.stringify(document, null, 2)}\n`;
    writeFileSync(tree.signingKey, serialised);
    return serialised;
  }

  afterAll(async () => {
    await Promise.all(started.map(stopIssuer));
    for (const root of scratchRoots) {
      rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });

  it(
    'writes the signing key when the bind does succeed, so the absence cases are not vacuous',
    async () => {
      // Same tree and env; nothing holds the port. A tree that cannot write a key at all would
      // make every absence assertion vacuous.
      const tree = isolatedIssuer();
      const child = startIssuerIn(tree, await freePort());

      try {
        expect(await waitForOutput(child, ISSUER_STARTED)).toContain('access token');
        expect(
          existsSync(tree.signingKey),
          'a run that started left no signing key on disk, so this tree cannot produce one and the held-port cases prove nothing about ordering'
        ).toBe(true);
        expect(
          existsSync(tree.inspectorConfig),
          'a run that started left no Inspector config, so the absence of one after a failed bind means nothing either'
        ).toBe(true);
      } finally {
        await stopIssuer(child);
      }
    },
    ISSUER_RUN_TIMEOUT_MS
  );

  it(
    'generates no signing key when the key set port is already held',
    async () => {
      // No key on disk: the case that pins the shipped defect.
      const tree = isolatedIssuer();
      const before = tree.contents();
      const holder = await holdPort();

      try {
        const result = runIssuerIn(tree, holder.port);

        // Right reason first. A missing cert or scrubbed variable also exits 1 without exercising order.
        expect(result.error).toBeUndefined();
        expect(
          result.stderr,
          `the run did not refuse at the bind, so what follows is not a statement about ordering. It printed: ${result.stderr}${result.stdout}`
        ).toContain(ADDRESS_IN_USE);
        expect(result.status).toBe(1);

        expect(
          existsSync(tree.signingKey),
          'a run that refused to start persisted a newly generated signing key when there was none, under a message promising nothing was changed; disk then names a key the running issuer is not serving the public half of'
        ).toBe(false);
        expect(
          existsSync(tree.inspectorConfig),
          'the run wrote an Inspector config carrying a token it never printed'
        ).toBe(false);

        // No path written, not just no named path.
        expect(
          tree.contents(),
          'a run that refused to start wrote something into the issuer directory. Whatever it is, the message that run printed says nothing was changed'
        ).toEqual(before);
      } finally {
        await holder.release();
      }
    },
    ISSUER_RUN_TIMEOUT_MS
  );

  it(
    'leaves a signing key that is already there byte-identical when the port is held',
    async () => {
      // Load path only: green under either ordering. The case above pins the shipped defect.
      const tree = isolatedIssuer();
      const seeded = await seedSigningKey(tree);
      const before = tree.contents();
      const holder = await holdPort();

      try {
        const result = runIssuerIn(tree, holder.port);

        expect(result.error).toBeUndefined();
        expect(
          result.stderr,
          `the run did not refuse at the bind, so what follows is not a statement about ordering. It printed: ${result.stderr}${result.stdout}`
        ).toContain(ADDRESS_IN_USE);
        expect(result.status).toBe(1);

        expect(
          readFileSync(tree.signingKey, 'utf8'),
          'a run that refused to start rewrote the signing key it found, so every token the running issuer already handed out stops verifying against the key set it is still serving'
        ).toBe(seeded);
        expect(
          existsSync(tree.inspectorConfig),
          'the run wrote an Inspector config carrying a token it never printed'
        ).toBe(false);

        // No path written, not just no named path.
        expect(
          tree.contents(),
          'a run that refused to start wrote something into the issuer directory. Whatever it is, the message that run printed says nothing was changed'
        ).toEqual(before);
      } finally {
        await holder.release();
      }
    },
    ISSUER_RUN_TIMEOUT_MS
  );
});
