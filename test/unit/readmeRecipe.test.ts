/**
 * README recipe vs `loadConfig` and vs the rest of the document.
 * Loadability: recipe, variable table, and required set must not drift (a ninth required
 * variable would tell a clone to run something that refuses to start).
 * Coherence: loading is weaker than working — expected values are parsed from the README, not
 * restated here, so two halves of one document cannot disagree.
 * Env is scrubbed, not overwritten: a shell leftover would make an incomplete recipe pass.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config/index.ts';

const README = readFileSync(fileURLToPath(new URL('../../README.md', import.meta.url)), 'utf8');

/** Anchored on a variable only the recipe block carries, so the table's rows cannot be mistaken for it. */
const RECIPE_ANCHOR = 'MCP_RESOURCE_IDENTIFIER=';

/** Everything `loadConfig` can read. `MCP_*` is a prefix sweep; `PORT` is the one that is not. */
const PORT_VAR = 'PORT';

/**
 * Loopback names: a fact about the internet, not the README, so this is the one hand-written
 * list. Count pinned so a fourth entry cannot quietly allow an off-machine recipe.
 */
const LOOPBACK_HOSTS: readonly string[] = ['localhost', '127.0.0.1', '::1'];

/** Every fenced body in the document. Odd indexes of the split are the insides of the fences. */
function fencedBlocks(): readonly string[] {
  return README.split('```').filter((_block, index) => index % 2 === 1);
}

function recipeBlock(): string {
  const found = fencedBlocks().filter((block) => block.includes(RECIPE_ANCHOR));
  expect(
    found,
    'exactly one fenced block in the README assigns the resource identifier. Zero means the recipe was renamed or removed and this whole file is asserting over nothing; more than one means the anchor no longer identifies it'
  ).toHaveLength(1);
  return found[0] ?? '';
}

function recipeVariables(): ReadonlyMap<string, string> {
  const entries = new Map<string, string>();
  for (const line of recipeBlock().split('\n')) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (match !== null) entries.set(match[1] ?? '', match[2] ?? '');
  }
  return entries;
}

/**
 * One pattern, every occurrence must agree. Two shells share `openssl`; a diverged block
 * would mint a different cert and a TLS error nobody could reproduce.
 */
function theOneValueOf(pattern: RegExp, what: string): string {
  const found = [...README.matchAll(pattern)].map((match) => match[1] ?? '');
  expect(
    found.length,
    `the README no longer states ${what}, so the case below is asserting over nothing — the recipe was reworded and this parser did not follow it`
  ).toBeGreaterThan(0);
  expect(
    [...new Set(found)],
    `the README states ${what} more than once and the statements disagree: ${found.join(' vs ')}`
  ).toHaveLength(1);
  return found[0] ?? '';
}

/**
 * SAN hosts from step 2. A JWKS host outside this list fails the handshake and looks like the
 * README's missing-`NODE_EXTRA_CA_CERTS` error — the wrong cause.
 */
function certificateHostNames(): readonly string[] {
  const value = theOneValueOf(/subjectAltName=([^"']+)/g, "the certificate's subjectAltName");
  return value.split(',').map((entry) => entry.trim().replace(/^(?:DNS|IP):/, ''));
}

/** The address the README tells the reader to open the Inspector's web UI on. */
function inspectorWebUiUrl(): URL {
  return new URL(theOneValueOf(/opens the web UI on `([^`]+)`/g, "the Inspector's web UI address"));
}

/**
 * `/mcp` URLs in commands. Recipe block excluded: it is under test; answering from itself is
 * self-satisfying.
 */
function mcpEndpointUrls(): readonly URL[] {
  const recipe = recipeBlock();
  const urls: URL[] = [];
  for (const block of fencedBlocks()) {
    if (block === recipe) continue;
    for (const match of block.matchAll(/https?:\/\/[^\s'"`]+/g)) {
      let url: URL;
      try {
        url = new URL(match[0]);
      } catch {
        continue;
      }
      // Path-equality, not a suffix test: the discovery document's address also ends in `/mcp`.
      if (url.pathname === '/mcp') urls.push(url);
    }
  }
  return urls;
}

/**
 * One spelling for a CLI path: shells disagree on `\` vs `/` and a leading `./`.
 */
function normalisePath(raw: string): string {
  return raw.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '');
}

/** The directory part of a path, in the same normalised spelling. */
function parentOf(raw: string): string {
  const path = normalisePath(raw);
  const at = path.lastIndexOf('/');
  return at === -1 ? '.' : path.slice(0, at);
}

/**
 * Directory step 2 creates. Derived from both `mkdir` forms so this file cannot agree with
 * itself while the README moves.
 */
function generatedDirectory(): string {
  const bash = theOneValueOf(/mkdir\s+-p\s+(\S+)/g, 'the directory the bash recipe creates');
  const powershell = theOneValueOf(
    /New-Item\s+-ItemType\s+Directory\s+-Force\s+(\S+)/g,
    'the directory the PowerShell recipe creates'
  );
  expect(
    normalisePath(powershell),
    'the bash and PowerShell forms of step 2 create different directories, so one of the two shells generates into a directory the rest of the recipe never names'
  ).toBe(normalisePath(bash));
  return normalisePath(bash);
}

/**
 * Access-restriction commands keyed by tool. `icacls` only in rewriting form: a later read-back
 * is not protecting anything.
 */
function protectionTargets(): ReadonlyMap<string, readonly string[]> {
  const commands: readonly (readonly [string, RegExp])[] = [
    ['chmod', /\bchmod\s+[0-7]{3,4}\s+(\S+)/g],
    ['icacls', /\bicacls\s+(\S+)\s+\/inheritance:r\b/g],
  ];
  return new Map(
    commands.map(([name, pattern]) => [
      name,
      [...README.matchAll(pattern)].map((match) => normalisePath(match[1] ?? '')),
    ])
  );
}

/**
 * Issuer command: a fact about this repo's scripts, not the README. Exactly one step must run
 * it, or a rename makes the ordering case vacuous.
 */
const ISSUER_COMMAND = 'npm run token:test';

/** Escapes a literal for embedding in a `RegExp`. The generated directory carries a `.`. */
function escapeForRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Numbered recipe steps. `### <n>. ` is unique among headings; last step ends at the next
 * `## `, not EOF, or it would swallow every later fence.
 */
function recipeSteps(): ReadonlyMap<number, string> {
  const headings = [...README.matchAll(/^### (\d+)\. /gm)];
  const steps = new Map<number, string>();

  headings.forEach((heading, index) => {
    const start = heading.index;
    const nextSection = README.indexOf('\n## ', start);
    const bounds = [
      headings[index + 1]?.index,
      nextSection === -1 ? undefined : nextSection,
    ].filter((bound): bound is number => bound !== undefined);
    steps.set(
      Number(heading[1]),
      README.slice(start, bounds.length > 0 ? Math.min(...bounds) : README.length)
    );
  });

  return steps;
}

/** One pattern for a path inside the generated directory, in either shell's separator. */
function generatedPathPattern(): RegExp {
  return new RegExp(`(?:\\./)?${escapeForRegExp(generatedDirectory())}[/\\\\][A-Za-z0-9._-]+`, 'g');
}

/** Every file the recipe puts in the generated directory, named anywhere in the document. */
function generatedPaths(): readonly string[] {
  return [
    ...new Set(
      [...README.matchAll(generatedPathPattern())].map((match) => normalisePath(match[0]))
    ),
  ];
}

/**
 * First-existence step per generated file. Two writers: openssl `-keyout`/`-out` in their step,
 * everything else in the issuer step. Derived so a moved step or renamed file moves with it.
 */
function creationSteps(): ReadonlyMap<string, number> {
  const steps = recipeSteps();

  // Fences only: prose mentions writers in steps that do not run them.
  const stepRunning = (needle: string): number => {
    const matching = [...steps].filter(([, text]) =>
      fencesWithin(text).some((block) => block.includes(needle))
    );
    expect(
      matching,
      `exactly one step must run \`${needle}\`. Zero means the recipe was reworded past this parser and the ordering case is asserting over nothing; more than one means it no longer identifies a single creation point`
    ).toHaveLength(1);
    return matching[0]?.[0] ?? 0;
  };

  const opensslStep = stepRunning('-keyout');
  const issuerStep = stepRunning(ISSUER_COMMAND);

  const created = new Map<string, number>();
  for (const path of generatedPaths()) created.set(path, issuerStep);
  for (const flag of [/-keyout\s+(\S+)/g, /-out\s+(\S+)/g]) {
    for (const match of README.matchAll(flag)) {
      created.set(normalisePath(match[1] ?? ''), opensslStep);
    }
  }

  return created;
}

/** The fenced bodies inside one step, which is where its commands are and its prose is not. */
function fencesWithin(text: string): readonly string[] {
  return text.split('```').filter((_block, index) => index % 2 === 1);
}

/** Every generated path named by a command, paired with the step whose commands name it. */
function pathUsagesByStep(): readonly { readonly path: string; readonly step: number }[] {
  const usages: { path: string; step: number }[] = [];

  for (const [step, text] of recipeSteps()) {
    for (const block of fencesWithin(text)) {
      for (const match of block.matchAll(generatedPathPattern())) {
        usages.push({ path: normalisePath(match[0]), step });
      }
    }
  }

  return usages;
}

/**
 * Full `icacls` rewrite lines (flags included). `protectionTargets` drops them; `/T` needs them.
 */
function protectionInvocations(): readonly string[] {
  return [...README.matchAll(/^.*\bicacls\s+\S+\s+\/inheritance:r.*$/gm)].map((match) => match[0]);
}

const saved = new Map<string, string | undefined>();

/** Assigning `undefined` would store the literal string, which is a present value. */
function unset(name: string): void {
  if (!saved.has(name)) saved.set(name, process.env[name]);
  Reflect.deleteProperty(process.env, name);
}

function set(name: string, value: string): void {
  if (!saved.has(name)) saved.set(name, process.env[name]);
  process.env[name] = value;
}

beforeEach(() => {
  saved.clear();
  for (const name of Object.keys(process.env)) {
    if (name.startsWith('MCP_')) unset(name);
  }
  unset(PORT_VAR);
  for (const [name, value] of recipeVariables()) set(name, value);
});

afterEach(() => {
  for (const [name, value] of saved) {
    if (value === undefined) Reflect.deleteProperty(process.env, name);
    else process.env[name] = value;
  }
  saved.clear();
});

describe("the README's local development recipe", () => {
  it('names enough variables to be a recipe at all', () => {
    // Anti-vacuity: empty parse would pass only if loadConfig required nothing.
    expect(
      [...recipeVariables().keys()],
      'the recipe block must parse into named assignments, or every case in this file is asserting over an empty map'
    ).toContain(PORT_VAR);
    expect(recipeVariables().size).toBeGreaterThanOrEqual(8);
  });

  it('starts the server: every variable the loader requires is in it, and every value is accepted', () => {
    // Loader-required vars missing from the README fail here, not in a clone's terminal.
    const config = loadConfig();

    expect(config.port).toBe(3000);
    expect(config.resourceIdentifier).toBe('https://localhost:3000/mcp');
    expect(config.jwksUrl.protocol).toBe('https:');
  });

  it('carries no variable the loader does not read, so the recipe cannot quietly grow', () => {
    // Other direction: leftover README vars that the loader dropped teach inert setup.
    for (const name of recipeVariables().keys()) {
      Reflect.deleteProperty(process.env, name);
      expect(
        () => loadConfig(),
        `${name} is in the README recipe but removing it does not stop startup, so the recipe is teaching a reader to set a variable nothing reads`
      ).toThrow();
      set(name, recipeVariables().get(name) ?? '');
    }
  });

  it('points the key set at a host the step-2 certificate covers, and at nothing off the machine', () => {
    // Loader pins scheme only. Cert SAN and JWKS host live in two places.
    const { hostname } = loadConfig().jwksUrl;

    expect(
      certificateHostNames(),
      `MCP_JWKS_URL names ${hostname}, which the openssl command in step 2 does not put in subjectAltName — the key set fetch fails the TLS handshake and reports it as an untrusted certificate`
    ).toContain(hostname);

    // A public-name SAN would pass the case above while pointing a local recipe off-machine.
    for (const name of certificateHostNames()) {
      expect(
        LOOPBACK_HOSTS,
        `the step-2 certificate is issued for ${name}, which is not a loopback name — a local recipe must not stand up a trust anchor for an address off this machine`
      ).toContain(name);
    }
    expect(LOOPBACK_HOSTS).toHaveLength(3);
  });

  it('names an explicit port for the key set, because the issuer binds the one it finds there', () => {
    // Issuer binds this port; no port would look like 443, which it cannot bind unprivileged.
    expect(
      loadConfig().jwksUrl.port,
      'MCP_JWKS_URL must carry an explicit port: the local issuer binds the port in this value and refuses to start without one'
    ).not.toBe('');
  });

  it('serves the key set from the same issuer the tokens name, and publishes that issuer', () => {
    // One process mints and serves. Drift here refuses every token on signature.
    const config = loadConfig();
    const jwksOrigin = config.jwksUrl.origin;

    expect(
      new URL(config.expectedIssuer).origin,
      'MCP_EXPECTED_ISSUER and MCP_JWKS_URL name different origins, but one local process answers for both'
    ).toBe(jwksOrigin);

    // Two vars: claim check vs published issuer. Same origin, not the same string.
    expect(
      new URL(config.authServerUrl).origin,
      'MCP_AUTH_SERVER_URL points the discovery document at an origin no local issuer is listening on'
    ).toBe(jwksOrigin);
  });

  it("allows the origin the README tells the reader to open the Inspector's web UI on", () => {
    // Browser client sends this origin; missing it is 403 before auth.
    const inspector = inspectorWebUiUrl();
    const config = loadConfig();

    expect(
      config.allowedOriginHostnames,
      `the README opens the Inspector on ${inspector.href} but ${inspector.hostname} is not on MCP_ALLOWED_ORIGINS, so every request it makes is rejected 403`
    ).toContain(inspector.hostname);

    // Loader reduces to hostnames; this pins the README's full origin claim.
    expect(
      (recipeVariables().get('MCP_ALLOWED_ORIGINS') ?? '').split(',').map((entry) => entry.trim()),
      `MCP_ALLOWED_ORIGINS does not carry ${inspector.origin} verbatim`
    ).toContain(inspector.origin);
  });

  it('mints an audience that agrees with the /mcp address its own commands dial', () => {
    // Identifier vs endpoint: mismatch mints an audience this server 401s.
    const endpoints = mcpEndpointUrls();
    expect(
      endpoints.length,
      'no /mcp address found in the README outside the recipe block, so this case is asserting over nothing'
    ).toBeGreaterThan(0);
    expect(
      [...new Set(endpoints.map((url) => url.href))],
      `the README dials more than one /mcp address: ${endpoints.map((url) => url.href).join(', ')}`
    ).toHaveLength(1);

    const endpoint = endpoints[0] ?? new URL('http://unreachable.invalid/mcp');
    const config = loadConfig();
    const identifier = new URL(config.resourceIdentifier);

    // Host and path only. Schemes differ on purpose: identifier is audience, not a dialled URL.
    expect(
      `${identifier.host}${identifier.pathname}`,
      `MCP_RESOURCE_IDENTIFIER is ${identifier.href} but the README dials ${endpoint.href}; the issuer mints that identifier as the audience and this server checks it, so the mismatch is a 401`
    ).toBe(`${endpoint.host}${endpoint.pathname}`);

    expect(
      endpoint.port,
      `the README dials port ${endpoint.port} but PORT is ${String(config.port)}, so nothing is listening where the commands point`
    ).toBe(String(config.port));
  });

  it('trusts the certificate file the openssl step actually writes', () => {
    // Step 2 write path vs step 4 trust path; rename one and TLS fails as "untrusted", not missing.
    const written = theOneValueOf(/-out\s+(\S+)/g, 'the certificate output path');
    const trusted = theOneValueOf(
      /NODE_EXTRA_CA_CERTS\s*=\s*'?([^\s'`;]+)/g,
      'the trusted CA path'
    );

    expect(
      trusted,
      `step 4 trusts ${trusted} but step 2 writes the certificate to ${written}`
    ).toBe(written);
  });

  it('protects the directory it generates into, rather than a file that happens to be in it', () => {
    // Directory, not a file list: issuer also writes a signing key; a per-file list drifts.
    const directory = generatedDirectory();
    const targets = protectionTargets();

    for (const [command, paths] of targets) {
      expect(
        paths.length,
        `the README no longer runs ${command} to restrict access, so this case is asserting over nothing — either the step was dropped or it was reworded past this parser`
      ).toBeGreaterThan(0);
    }

    for (const [command, paths] of targets) {
      for (const path of paths) {
        expect(
          path,
          `${command} is aimed at ${path}, but the recipe generates into ${directory} — a step that names anything narrower leaves whatever else lands in that directory readable by every local account`
        ).toBe(directory);
      }
    }
  });

  it('generates every file into the directory the permissions step covers', () => {
    // Secrets must live in the protected directory, not beside it.
    const directory = generatedDirectory();
    const generated = [
      theOneValueOf(/-keyout\s+(\S+)/g, "the TLS key's path"),
      theOneValueOf(/-out\s+(\S+)/g, 'the certificate output path'),
      theOneValueOf(/NODE_EXTRA_CA_CERTS\s*=\s*'?([^\s'`;]+)/g, 'the trusted CA path'),
      theOneValueOf(/require\('([^']+)'\)/g, 'the Inspector config the token comes back out of'),
      theOneValueOf(/--config\s+(\S+)/g, 'the Inspector config the CLI is pointed at'),
    ];

    for (const path of generated) {
      expect(
        parentOf(path),
        `the recipe names ${path}, which is not in ${directory} — the permissions step covers that directory and nothing else, so this file is left unprotected`
      ).toBe(directory);
    }
  });

  it('names no file before the step that creates it', () => {
    // Ordered recipe. Naming a later file early is file-not-found (step 2 used to icacls the signing key).
    const created = creationSteps();
    const usages = pathUsagesByStep();

    expect(
      usages.length,
      'no command in any numbered step names a file in the generated directory, so this case is asserting over nothing — the steps or the fences were reworded past this parser'
    ).toBeGreaterThan(0);

    for (const { path, step } of usages) {
      const createdAt = created.get(path);

      // Missing writer: parser gap, not a pass.
      expect(
        createdAt,
        `step ${String(step)} names ${path}, but nothing in the README is documented as writing it — either a third writer appeared or the creation points were reworded past this parser`
      ).toBeDefined();

      expect(
        createdAt ?? Number.MAX_SAFE_INTEGER,
        `step ${String(step)} runs a command naming ${path}, but ${path} is not written until step ${String(createdAt)} — a reader following the recipe in order gets a file-not-found`
      ).toBeLessThanOrEqual(step);
    }
  });

  it('protects the directory without /T, which would empty the access list of every file in it', () => {
    // Measured: `/T` + `(OI)(CI)` on files empties the DACL (owner cannot read/rewrite).
    // Bare `/T` is also mangled by Git Bash to `T:/`. Pin absence — `/T` looks like the fix.
    const invocations = protectionInvocations();

    expect(
      invocations.length,
      'the README no longer rewrites the directory access list, so this case is asserting over nothing'
    ).toBeGreaterThan(0);

    // Same commands as `protectionTargets`, so a reword cannot be visible to only one parser.
    expect(
      invocations.length,
      'the two parsers of the icacls protection step disagree about how many there are, so one of them is missing an invocation the other can see'
    ).toBe(protectionTargets().get('icacls')?.length);

    for (const invocation of invocations) {
      expect(
        invocation,
        `this invocation carries /T: ${invocation.trim()} — on a file (OI)(CI) grants nothing while /inheritance:r strips the inherited entries, so /T leaves every file in the directory with an empty access list that the owner cannot read or rewrite`
      ).not.toMatch(/\s\/T\b/);
    }
  });
});
