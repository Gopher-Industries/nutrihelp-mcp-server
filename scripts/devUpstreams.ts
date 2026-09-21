/**
 * Local stand-ins for the two services this server dials out to, so a local run reaches a real
 * tool call instead of stopping at the live grant check.
 *
 *   authorization server   the key set, RFC 7662 introspection, RFC 8693 exchange
 *   stand-in backend       the nutrition search endpoint
 *
 * It is the issuer plus the endpoints the issuer does not have, which is why it replaces rather
 * than accompanies it: one origin answers for the key set and for the authorization server, and
 * two processes cannot both hold that port. Key handling, the `.dev/` directory, the token
 * profile and the Inspector config all come from `issueTestToken.ts` rather than being repeated,
 * so a rejected token still cannot mean that a different key was served.
 *
 * NOT a second composition root. It imports nothing from `src/` but the frozen scope names, wires
 * no transport, registers no tool and dispatches nothing. It answers HTTP the way the two real
 * services are contracted to, and that is all.
 *
 * WARNING: local development only, and it is not a model of the real services. It verifies no
 * client assertion, checks no signature on the token it introspects, and hands out an exchanged
 * credential to anyone who asks. Never run it on an address something else can reach.
 */

import 'dotenv/config';

import { existsSync, writeFileSync } from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createServer } from 'node:https';
import { decodeJwt, type JWTPayload } from 'jose';
import { TOOL_SCOPES } from '../src/auth/scopes.ts';
import {
  bind,
  derivePublicJwk,
  DEV_DIR,
  DEV_TOKEN_LIFETIME,
  DEV_TOKEN_SCOPES,
  DEV_TOKEN_SUBJECT,
  isEntrypoint,
  jwksAddress,
  jwksKeySetUrl,
  loadOrCreateKeyPair,
  readEnv,
  readFileOrExplain,
  TLS_CERT_FILE,
  TLS_KEY_FILE,
  writeInspectorConfig,
} from './issueTestToken.ts';
import { makeToken } from './makeToken.ts';

/**
 * The two paths the composition root builds against the authorization server's origin, and the
 * one the nutrition tool builds against the backend's. Restated here because a dev stand-in must
 * not import the modules it stands in for; they are checked at startup against nothing, so a
 * rename in either place shows up as a 404 in this process's own log.
 */
const INTROSPECTION_PATH = '/api/oauth/introspect';
const TOKEN_EXCHANGE_PATH = '/api/oauth/token';
const FOOD_SEARCH_PATH = '/api/fooddata/search';

/** Present means the user disconnected. Read per request, so the toggle needs no restart. */
const REVOKED_FILE = `${DEV_DIR}REVOKED`;

/** The printed token, on disk as well, so a driver in any shell can read it without scraping. */
const TOKEN_FILE = `${DEV_DIR}token.txt`;

/** A second token, deliberately short of the scope the nutrition tool requires. */
const NARROW_TOKEN_FILE = `${DEV_DIR}token-narrow-scope.txt`;

/**
 * What the exchange hands back. A fixed opaque string, not a token: the point of reading it in
 * the backend log is to see that the inbound token was NOT the thing forwarded.
 */
const EXCHANGED_CREDENTIAL = 'local-dev-exchanged-credential';

/** Seconds. Short, like the real one; the cache retires an entry before this elapses. */
const EXCHANGED_CREDENTIAL_LIFETIME_S = 120;

/**
 * Every frozen scope except the one the nutrition tool requires, derived rather than named: the
 * narrow token has to stay short of that tool as tools and scopes are added.
 */
const NARROW_TOKEN_SCOPES: readonly string[] = DEV_TOKEN_SCOPES.filter(
  (scope) => scope !== TOOL_SCOPES.nutrition_lookup
);

/**
 * Rows the stand-in backend answers with.
 *
 * Three, so a row ceiling has something to cut. Each one carries two fields the nutrition tool's
 * allowlist does not name — `internal_id` and `supplier_email` — because an allowlist that is
 * never handed anything to drop looks exactly like no allowlist at all. Neither reaches the
 * model, and a run where either one does is the finding this shape exists to produce.
 */
function foodRows(query: string): readonly Readonly<Record<string, unknown>>[] {
  return [
    {
      id: 101,
      internal_id: 'row-101',
      supplier_email: 'buyer@supplier.invalid',
      category: 'fruit',
      name: `${query} (raw)`,
      calories: 52,
      fat: 0.2,
      carbohydrates: 14,
      protein: 0.3,
      fiber: 2.4,
      sodium: 1,
      sugar: 10.4,
      serving_size: '100 g',
    },
    {
      id: 102,
      internal_id: 'row-102',
      supplier_email: 'buyer@supplier.invalid',
      category: 'juice',
      name: `${query} juice`,
      calories: 46,
      fat: 0.1,
      carbohydrates: 11,
      protein: 0.1,
      fiber: 0.2,
      sodium: 4,
      sugar: 9.6,
      serving_size: '100 ml',
    },
    {
      id: 103,
      internal_id: 'row-103',
      supplier_email: 'buyer@supplier.invalid',
      category: 'condiment',
      name: `${query} sauce`,
      calories: 68,
      fat: 0.1,
      carbohydrates: 17,
      protein: 0.2,
      fiber: 1.3,
      sodium: 2,
      sugar: 14.8,
      serving_size: '100 g',
    },
  ];
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    let raw = '';
    request.on('data', (chunk: Buffer) => {
      raw += chunk.toString('utf8');
    });
    request.on('end', () => {
      resolve(raw);
    });
  });
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

/** Path only. `request.url` carries the query string that `URL.pathname` does not. */
function pathOf(request: IncomingMessage, origin: string): URL {
  return new URL(request.url ?? '/', origin);
}

function matches(request: IncomingMessage, method: string, url: URL, path: string): boolean {
  return request.method === method && url.pathname === path;
}

/**
 * The token's own identity, decoded and not verified.
 *
 * Decoding rather than verifying is the honest shape for a stand-in: this process signed the
 * token seconds earlier, so verifying it here would only test itself. What matters is that the
 * answer ECHOES the presented token's subject, client and grant rather than asserting fixed
 * values — the scope step compares all three against the token and refuses a mismatch, so a
 * stand-in that answered with its own constants would fail the demo for a reason the demo is not
 * about.
 */
function claimsOf(token: string): JWTPayload | undefined {
  try {
    return decodeJwt(token);
  } catch {
    return undefined;
  }
}

function revoked(): boolean {
  return existsSync(REVOKED_FILE);
}

/**
 * What arrived on the backend call, in words.
 *
 * Three answers and not two. A tool whose backing endpoint is public is called with NO credential
 * on purpose — exchanging one for a public read would widen the blast radius for nothing — so an
 * absent header is the correct outcome for the nutrition tool today and must not read as an
 * alarm. The exchanged credential is what a credentialed tool will present. Anything else is the
 * finding: the one thing that must never appear here is the token the client sent inbound.
 */
function describeCredential(request: IncomingMessage): string {
  const header = request.headers.authorization;
  if (header === undefined || header === '') {
    return 'none, which is correct for a public backing endpoint';
  }
  const presented = header.replace(/^Bearer /i, '');
  return presented === EXCHANGED_CREDENTIAL
    ? 'the exchanged credential'
    : 'NOT the exchanged credential and not nothing - read this line before going further';
}

interface Address {
  readonly hostname: string;
  readonly port: number;
}

/** Explicit https and an explicit port: this process binds what it finds and will not bind 443. */
function backendAddress(): { readonly base: URL; readonly address: Address } {
  const raw = readEnv('NUTRIHELP_API_BASE_URL');
  const base = new URL(raw);
  if (base.protocol !== 'https:') {
    throw new Error(
      `NUTRIHELP_API_BASE_URL must be https for this stand-in: it is served from the same local ` +
        `certificate as the key set, and the server refuses a plain-http upstream. Got ${raw}.`
    );
  }
  if (base.port === '') {
    throw new Error(
      `NUTRIHELP_API_BASE_URL must name an explicit port, for example https://127.0.0.1:9443 — ` +
        'this stand-in binds the port it finds there.'
    );
  }
  return { base, address: { hostname: base.hostname, port: Number.parseInt(base.port, 10) } };
}

/**
 * One process answers for the key set and for the authorization server, so the two values have to
 * name one origin. They are separate variables because they mean different things in a deployment,
 * which is exactly why they can drift here without anything else noticing.
 */
function authorizationServerOrigin(keySetUrl: URL): string {
  const authServerUrl = new URL(readEnv('MCP_AUTH_SERVER_URL'));
  if (authServerUrl.origin !== keySetUrl.origin) {
    throw new Error(
      `MCP_AUTH_SERVER_URL is ${authServerUrl.origin} and MCP_JWKS_URL is ${keySetUrl.origin}, ` +
        'but this stand-in serves both from one listener. Point them at the same origin.'
    );
  }
  return authServerUrl.origin;
}

function inUseMessage(what: string, address: Address): string {
  return (
    `${address.hostname}:${String(address.port)} is already in use, so the ${what} did not ` +
    'start and nothing was changed. Something is almost certainly already serving there — ' +
    'stop it first, and this will print a fresh token when it restarts.'
  );
}

async function main(): Promise<void> {
  const keySetUrl = jwksKeySetUrl();
  const issuer = readEnv('MCP_EXPECTED_ISSUER');
  const authServerOrigin = authorizationServerOrigin(keySetUrl);
  // Same normalisation the server applies before comparing `aud`.
  const audience = new URL(readEnv('MCP_RESOURCE_IDENTIFIER')).href;
  const port = readEnv('PORT');
  const { base: backendBase, address: backendAt } = backendAddress();

  // Fail on a missing certificate before generating a key pair, and long before binding.
  const tlsKey = readFileOrExplain(TLS_KEY_FILE, 'local TLS key');
  const tlsCert = readFileOrExplain(TLS_CERT_FILE, 'local TLS certificate');
  const tls = { key: tlsKey, cert: tlsCert };

  const { key, persist } = await loadOrCreateKeyPair();
  const keySet = { keys: [await derivePublicJwk(key.privateKey, key.kid, key.alg)] };

  const authorizationServer = createServer(tls, (request, response) => {
    void (async (): Promise<void> => {
      const url = pathOf(request, authServerOrigin);
      const tag = `  authorization server  ${request.method ?? '?'} ${url.pathname}`;

      if (matches(request, 'GET', url, keySetUrl.pathname)) {
        sendJson(response, 200, keySet);
        console.log(`${tag}  -> 200 key set, one key, kid ${key.kid}`);
        return;
      }

      if (matches(request, 'POST', url, INTROSPECTION_PATH)) {
        const presented = new URLSearchParams(await readBody(request)).get('token') ?? '';
        if (revoked()) {
          sendJson(response, 200, { active: false });
          console.log(`${tag}  -> 200 active:false, because ${REVOKED_FILE} is present`);
          return;
        }
        const claims = claimsOf(presented);
        if (claims === undefined) {
          // No grant can be named for something that is not a token. Inactive is the answer.
          sendJson(response, 200, { active: false });
          console.log(`${tag}  -> 200 active:false, the presented value is not a token`);
          return;
        }
        sendJson(response, 200, {
          active: true,
          scope: claims.scope,
          sub: claims.sub,
          client_id: claims.client_id,
          grant_id: claims.grant_id,
        });
        console.log(
          `${tag}  -> 200 active:true, echoing sub=${String(claims.sub)} ` +
            `grant=${String(claims.grant_id)}`
        );
        return;
      }

      if (matches(request, 'POST', url, TOKEN_EXCHANGE_PATH)) {
        // Nothing reaches this today: the only registered tool reads a public endpoint, and a
        // public read is called with no credential on purpose. It is served anyway, because the
        // first tool that declares a credentialed backing endpoint needs it and would otherwise
        // fail here with a 404 that looks like a defect in the server rather than a gap here.
        await readBody(request);
        sendJson(response, 200, {
          access_token: EXCHANGED_CREDENTIAL,
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: EXCHANGED_CREDENTIAL_LIFETIME_S,
        });
        console.log(
          `${tag}  -> 200 exchanged credential, ${String(EXCHANGED_CREDENTIAL_LIFETIME_S)}s`
        );
        return;
      }

      sendJson(response, 404, { error: 'not_found' });
      console.log(`${tag}  -> 404, nothing here serves that path`);
    })();
  });

  const backend = createServer(tls, (request, response) => {
    const url = pathOf(request, backendBase.origin);
    const tag = `  stand-in backend      ${request.method ?? '?'} ${url.pathname}`;

    if (matches(request, 'GET', url, FOOD_SEARCH_PATH)) {
      // The tool parses `{ data: [...] }` and reads anything else as a retryable upstream
      // failure, so the envelope is part of the contract rather than decoration.
      sendJson(response, 200, { data: foodRows(url.searchParams.get('query') ?? '') });
      console.log(`${tag}${url.search}  -> 200, three rows`);
      console.log(`                          credential presented: ${describeCredential(request)}`);
      console.log(
        `                          correlation id: ${String(request.headers['x-correlation-id'])}`
      );
      return;
    }

    sendJson(response, 404, { error: 'not_found' });
    console.log(`${tag}  -> 404, this stand-in serves ${FOOD_SEARCH_PATH} and nothing else`);
  });

  // Bind before writing anything: a run that cannot serve must leave no key, no token and no
  // Inspector config behind, because every one of them would name a listener that is not there.
  const keySetAt = jwksAddress(keySetUrl);
  await bind(
    authorizationServer,
    keySetAt.hostname,
    keySetAt.port,
    inUseMessage('authorization server', keySetAt)
  );
  await bind(
    backend,
    backendAt.hostname,
    backendAt.port,
    inUseMessage('stand-in backend', backendAt)
  );
  persist?.();

  const tokenProfile = {
    key,
    iss: issuer,
    aud: audience,
    sub: DEV_TOKEN_SUBJECT,
    exp: DEV_TOKEN_LIFETIME,
  };
  const token = await makeToken({ ...tokenProfile, scopes: DEV_TOKEN_SCOPES });
  const narrowToken = await makeToken({ ...tokenProfile, scopes: NARROW_TOKEN_SCOPES });

  // Bearer credentials: whoever holds one is this user as far as the server is concerned, so
  // they get the signing key's mode rather than a file's default (inert on Windows, where the
  // directory's access list is what protects them).
  writeFileSync(TOKEN_FILE, `${token}\n`, { mode: 0o600 });
  writeFileSync(NARROW_TOKEN_FILE, `${narrowToken}\n`, { mode: 0o600 });
  writeInspectorConfig(`http://localhost:${port}/mcp`, token);

  console.log(`key set:              ${keySetUrl.href}`);
  console.log(`introspection:        ${authServerOrigin}${INTROSPECTION_PATH}`);
  console.log(`exchange:             ${authServerOrigin}${TOKEN_EXCHANGE_PATH}`);
  console.log(`stand-in backend:     ${backendBase.origin}${FOOD_SEARCH_PATH}`);
  console.log(`issuer:               ${issuer}`);
  console.log(`audience:             ${audience}`);
  console.log(`token:                ${TOKEN_FILE}`);
  console.log(`token, narrow scope:  ${NARROW_TOKEN_FILE}`);
  console.log('');
  console.log(`scopes in that token: ${DEV_TOKEN_SCOPES.join(' ')}`);
  console.log(`scopes in the other:  ${NARROW_TOKEN_SCOPES.join(' ')}`);
  console.log('');
  console.log(`access token, valid for ${DEV_TOKEN_LIFETIME}:`);
  console.log(token);
  console.log('');
  console.log(`To disconnect the grant:  create ${REVOKED_FILE}`);
  console.log('The next request is refused. Nothing restarts and no cache is cleared.');
  console.log('Delete that file and the same token works again.');
  console.log('');
  console.log('Leave this running. Every call the server makes is logged below as it arrives.');
}

/** Same guard as the issuer, for the same reason: an import must not bind two ports. */
if (isEntrypoint(import.meta.url)) {
  await main().catch((cause: unknown) => {
    console.error(cause instanceof Error ? cause.message : String(cause));
    process.exit(1);
  });
}
