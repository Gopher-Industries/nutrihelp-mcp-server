/**
 * Local issuer: one RS256 pair for the printed token and the JWKS it serves, so a reject is
 * never "wrong key vs wrong signature". Not a second composition root — fixture plus HTTPS file
 * server. Writes `.dev/` (git-ignored).
 */

import 'dotenv/config';

import { createServer, type Server } from 'node:https';
import { createPublicKey, KeyObject } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { exportJWK, importJWK, type JWK } from 'jose';
import { createTestKeyPair, makeToken, MCP_TOKEN_ALG, type TestKeyPair } from './makeToken.ts';

/** Git-ignored: signing key, TLS key, Inspector config. */
const DEV_DIR = fileURLToPath(new URL('../.dev/', import.meta.url));

const SIGNING_KEY_FILE = `${DEV_DIR}signing-key.json`;
const TLS_KEY_FILE = `${DEV_DIR}tls-key.pem`;
const TLS_CERT_FILE = `${DEV_DIR}tls-cert.pem`;
const INSPECTOR_CONFIG_FILE = `${DEV_DIR}inspector.json`;

/** Inspector config entry name. Web UI ignores `--server`; CLI/TUI need this. */
const INSPECTOR_SERVER_NAME = 'nutrihelp';

/** Stable kid for the local pair. Rotation is not rehearsed here. */
const DEV_KEY_ID = 'dev-issuer-key';

/** Session-length, not a grant. */
const DEV_TOKEN_LIFETIME = '1h';

/** Empty until frozen scopes land; a made-up name would read as a contract. */
const DEV_TOKEN_SCOPES: readonly string[] = [];

/** Dev subject. Not a real account. */
const DEV_TOKEN_SUBJECT = 'local-dev-user';

/** On-disk key: private half only. Older files may still have `publicJwk`; it is ignored. */
interface StoredSigningKey {
  readonly kid: string;
  readonly alg: string;
  readonly privateJwk: JWK;
}

/** Private-only JWK members. Serving any of these publishes the signing key. */
const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;

function readEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(
      `Missing required environment variable: ${name}. The issuer reads the same values the ` +
        'server does, so both agree on issuer, audience and key-set location.'
    );
  }
  return value.trim();
}

function readFileOrExplain(path: string, what: string): Buffer {
  try {
    return readFileSync(path);
  } catch {
    throw new Error(
      `Cannot read the ${what} at ${path}. Generate a local certificate first — the README ` +
        'section "Local development without a backend" carries the openssl command.'
    );
  }
}

/** Reuse the on-disk pair so restarts keep verifying the same tokens. */
function loadStoredKey(): StoredSigningKey | undefined {
  let raw: string;
  try {
    raw = readFileSync(SIGNING_KEY_FILE, 'utf8');
  } catch {
    return undefined;
  }
  // Corrupt or interrupted file: same remedy — delete it. Do not leak a raw SyntaxError.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = undefined;
  }
  if (!isStoredSigningKey(parsed)) {
    throw new Error(`${SIGNING_KEY_FILE} is not a key document. Delete it and run this again.`);
  }
  return parsed;
}

function isJwk(value: unknown): value is JWK {
  return typeof value === 'object' && value !== null;
}

function isStoredSigningKey(value: unknown): value is StoredSigningKey {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<Record<keyof StoredSigningKey, unknown>>;
  return (
    typeof candidate.kid === 'string' &&
    typeof candidate.alg === 'string' &&
    isJwk(candidate.privateJwk)
  );
}

/** Asymmetric only. A stored oct key fails here, not at SignJWT. */
async function toPrivateKey(jwk: JWK, alg: string): Promise<TestKeyPair['privateKey']> {
  // extractable: KeyObject.from warns on non-extractable CryptoKey. Private JWK is already in-process.
  const key = await importJWK(jwk, alg, { extractable: true });
  if (key instanceof Uint8Array) {
    throw new Error(
      `${SIGNING_KEY_FILE} holds a symmetric key. This server verifies against a public key ` +
        'and mints nothing symmetric. Delete the file and run this again.'
    );
  }
  return key;
}

/** Public JWK from the signing key. Disk is never the source of what is served. */
export async function derivePublicJwk(
  privateKey: TestKeyPair['privateKey'],
  kid: string,
  alg: string
): Promise<JWK> {
  const derived = await exportJWK(createPublicKey(KeyObject.from(privateKey)));
  const jwk: JWK = { ...derived, kid, alg, use: 'sig' };

  // Alarm if a later change serves a handed-in JWK instead of deriving one.
  const leaked = PRIVATE_JWK_MEMBERS.filter((member) => jwk[member] !== undefined);
  if (leaked.length > 0) {
    throw new Error(
      `Refusing to serve a key set carrying private key material (${leaked.join(', ')}). The ` +
        'published key set must be derived from the signing key, never copied from a field.'
    );
  }
  return jwk;
}

/** Same factory as the tests, so mint and JWKS cannot drift. */
async function loadOrCreateKeyPair(): Promise<TestKeyPair> {
  const stored = loadStoredKey();
  if (stored !== undefined) {
    const privateKey = await toPrivateKey(stored.privateJwk, stored.alg);
    return {
      kid: stored.kid,
      alg: stored.alg,
      privateKey,
      publicJwk: await derivePublicJwk(privateKey, stored.kid, stored.alg),
    };
  }

  const created = await createTestKeyPair(DEV_KEY_ID, MCP_TOKEN_ALG);
  const document: StoredSigningKey = {
    kid: created.kid,
    alg: created.alg,
    privateJwk: await exportJWK(created.privateKey),
  };
  // Private signing key: not world-readable (mode is inert on Windows).
  writeFileSync(SIGNING_KEY_FILE, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o600 });
  return created;
}

/** Refuse query/fragment: the server pins scheme only, and a 404 here looks like a cert-trust failure. */
function jwksKeySetUrl(): URL {
  const raw = readEnv('MCP_JWKS_URL');
  if (raw.includes('?') || raw.includes('#')) {
    throw new Error('MCP_JWKS_URL must carry no query string and no fragment.');
  }
  return new URL(raw);
}

/** Resolve after listen. EADDRINUSE means an issuer is already running — do not overwrite the token. */
function bind(server: Server, hostname: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    function onFailedBind(cause: Error): void {
      reject(
        (cause as NodeJS.ErrnoException).code === 'EADDRINUSE'
          ? new Error(
              `${hostname}:${String(port)} is already in use, so this issuer did not start and ` +
                'nothing was changed. An issuer is almost certainly already running there — stop ' +
                'it first, and it will print a fresh token when it restarts.'
            )
          : cause
      );
    }
    server.once('error', onFailedBind);
    server.listen(port, hostname, () => {
      // After bind, `error` is a runtime fault — do not reject an already-resolved promise.
      server.off('error', onFailedBind);
      server.on('error', (cause: Error) => {
        console.error(`key set server error: ${cause.message}`);
      });
      resolve();
    });
  });
}

/** Explicit port: this process will not bind 443. */
function jwksAddress(jwksUrl: URL): { readonly hostname: string; readonly port: number } {
  if (jwksUrl.port === '') {
    throw new Error(
      `MCP_JWKS_URL must name an explicit port, for example https://127.0.0.1:8443/jwks — this ` +
        'issuer binds the port it finds there.'
    );
  }
  return { hostname: jwksUrl.hostname, port: Number.parseInt(jwksUrl.port, 10) };
}

function writeInspectorConfig(mcpUrl: string, token: string): void {
  const config = {
    mcpServers: {
      [INSPECTOR_SERVER_NAME]: {
        type: 'http',
        url: mcpUrl,
        // Inspector defaults to legacy; this server refuses it.
        protocolEra: 'modern',
        // Web client refuses `--header` together with `--config`.
        headers: { Authorization: `Bearer ${token}` },
      },
    },
  };
  writeFileSync(INSPECTOR_CONFIG_FILE, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

async function main(): Promise<void> {
  const jwksUrl = jwksKeySetUrl();
  const issuer = readEnv('MCP_EXPECTED_ISSUER');
  // Same normalisation the server applies before comparing `aud`.
  const audience = new URL(readEnv('MCP_RESOURCE_IDENTIFIER')).href;
  const port = readEnv('PORT');

  // 0o700 is a floor on Unix; inert on Windows (see README icacls).
  mkdirSync(DEV_DIR, { recursive: true, mode: 0o700 });

  // Fail on a missing cert before writing a key pair.
  const tlsKey = readFileOrExplain(TLS_KEY_FILE, 'local TLS key');
  const tlsCert = readFileOrExplain(TLS_CERT_FILE, 'local TLS certificate');

  const key = await loadOrCreateKeyPair();
  const jwks = { keys: [await derivePublicJwk(key.privateKey, key.kid, key.alg)] };

  const server = createServer({ key: tlsKey, cert: tlsCert }, (request, response) => {
    // Path only: `request.url` includes the query string that `URL.pathname` does not.
    const requested = new URL(request.url ?? '/', jwksUrl).pathname;
    if (requested === jwksUrl.pathname) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(jwks));
      return;
    }
    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: 'not_found', serving: jwksUrl.pathname }));
  });

  // Bind first: a failed refresh must not replace inspector.json with a token nobody saw.
  const { hostname, port: jwksPort } = jwksAddress(jwksUrl);
  await bind(server, hostname, jwksPort);

  const token = await makeToken({
    key,
    iss: issuer,
    aud: audience,
    scopes: DEV_TOKEN_SCOPES,
    sub: DEV_TOKEN_SUBJECT,
    exp: DEV_TOKEN_LIFETIME,
  });

  writeInspectorConfig(`http://localhost:${port}/mcp`, token);

  console.log(`key set:          ${jwksUrl.href}`);
  console.log(`issuer:           ${issuer}`);
  console.log(`audience:         ${audience}`);
  console.log(`Inspector config: ${INSPECTOR_CONFIG_FILE} (server "${INSPECTOR_SERVER_NAME}")`);
  console.log('');
  console.log('access token, valid for one hour:');
  console.log(token);
  console.log('');
  console.log('Leave this running. The server needs the key set to verify that token.');
}

/**
 * True only when this file is the process entry. Unguarded import would bind the port and rewrite
 * `.dev/`. `import.meta.main` is 24.2+ (experimental); on 24.0/24.1 it is undefined and
 * `token:test` would exit 0 without issuing. Path compare holds for the whole engines range.
 * No `argv[1]` (`node -e`) is not this file — do not issue.
 */
function isEntrypoint(): boolean {
  const invoked = process.argv[1];
  return invoked !== undefined && pathToFileURL(invoked).href === import.meta.url;
}

/** Print the error sentence, not a stack: EADDRINUSE is the documented refresh path. */
if (isEntrypoint()) {
  await main().catch((cause: unknown) => {
    console.error(cause instanceof Error ? cause.message : String(cause));
    process.exit(1);
  });
}
