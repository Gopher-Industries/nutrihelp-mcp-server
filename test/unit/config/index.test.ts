/**
 * Startup validation. `loadConfig` reads `process.env` only. SCOPE is the variables it loads
 * today, not the full deployment set — a green run means those are held, not that nothing
 * security-relevant defaults anywhere.
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../../src/config/index.ts';
import { protectedResourceMetadataUrl } from '../../../src/auth/challenge.ts';
import {
  ALLOWED_ORIGIN,
  MCP_AUTH_SERVER_URL,
  MCP_EXPECTED_ISSUER,
  MCP_JWKS_URL,
  MCP_RESOURCE_IDENTIFIER,
} from '../../support/testEnv.ts';

/** Every variable this module requires. The list is the subject of the first test below: a
 *  variable dropped from the required set is a variable that silently becomes optional. */
const REQUIRED_VARS = [
  'PORT',
  'MCP_ALLOWED_ORIGINS',
  'MCP_JWKS_URL',
  'MCP_EXPECTED_ISSUER',
  'MCP_AUTH_SERVER_URL',
  'MCP_RESOURCE_IDENTIFIER',
  'MCP_JWKS_CACHE_TTL_S',
  'MCP_REQUEST_DEADLINE_MS',
] as const;

type RequiredVar = (typeof REQUIRED_VARS)[number];

/** A complete, valid deployment configuration in test clothing. */
const VALID: Record<RequiredVar, string> = {
  PORT: '3000',
  MCP_ALLOWED_ORIGINS: ALLOWED_ORIGIN,
  MCP_JWKS_URL: MCP_JWKS_URL,
  MCP_EXPECTED_ISSUER: MCP_EXPECTED_ISSUER,
  MCP_AUTH_SERVER_URL: MCP_AUTH_SERVER_URL,
  MCP_RESOURCE_IDENTIFIER: MCP_RESOURCE_IDENTIFIER,
  MCP_JWKS_CACHE_TTL_S: '600',
  MCP_REQUEST_DEADLINE_MS: '30000',
};

const WHOLE_NUMBER_VARS = ['MCP_JWKS_CACHE_TTL_S', 'MCP_REQUEST_DEADLINE_MS'] as const;

/** `parseInt` stops at the first non-digit; digits-only is what actually refuses these. */
const REFUSED_WHOLE_NUMBERS = [
  '10.5',
  '1e3',
  '60abc',
  '0x10',
  'abc',
  '-1',
  'NaN',
  'Infinity',
] as const;

/** The three variables read as URLs. All three go through one scheme check, so the case table
 *  asserts each rather than trusting that they share a code path. */
const URL_VARS = ['MCP_JWKS_URL', 'MCP_AUTH_SERVER_URL', 'MCP_RESOURCE_IDENTIFIER'] as const;

/** Identifiers carrying no resource path. The pointer is published at origin + well-known + path,
 *  so a bare origin publishes it somewhere the document does not live. */
const NO_RESOURCE_PATH = ['https://mcp.nutrihelp.test', 'https://mcp.nutrihelp.test/'] as const;

/**
 * Identifiers carrying userinfo. This is the one shape where `href` and `origin` + `pathname`
 * disagree — `origin` drops the credentials and `href` keeps them — so an identifier that passed
 * would make the stored audience carry a credential the published pointer does not, and the two
 * would never agree again.
 */
const WITH_USERINFO = [
  'https://user:pass@mcp.nutrihelp.test/mcp',
  'https://user@mcp.nutrihelp.test/mcp',
] as const;

/**
 * Identifiers carrying a query string or a fragment.
 *
 * The last two are the only shapes that separate a raw-string test from a parsed one: a value
 * ending in a bare `?` or a bare `#` parses to an empty `search` and an empty `hash` while `href`
 * keeps the character, so a check written against the parsed fields accepts a form it reads as
 * refusing — and stores the character in the audience.
 */
const PUBLISHED_IDENTIFIER_VARS = ['MCP_RESOURCE_IDENTIFIER', 'MCP_AUTH_SERVER_URL'] as const;

/**
 * Resource paths carrying a character Express re-reads as route-pattern syntax. The metadata route
 * is derived from this path, so `:` becomes a parameter and `*` a wildcard — the document then
 * answers at addresses no pointer names, which is the drift the derivation exists to prevent —
 * while `(` throws inside the router at startup naming neither the variable nor the cause.
 */
const ROUTE_METACHARACTER_PATHS = [
  'https://mcp.nutrihelp.test/mcp:v1',
  'https://mcp.nutrihelp.test/a*b',
  'https://mcp.nutrihelp.test/mcp(1)',
  'https://mcp.nutrihelp.test/mcp)x',
  'https://mcp.nutrihelp.test/mcp+1',
  'https://mcp.nutrihelp.test/mcp[1]',
  'https://mcp.nutrihelp.test/mcp]x',
] as const;

/**
 * `{` and `}` omitted: `new URL()` percent-encodes them in pathname, so they never reach the router as syntax.
 */

const QUERY_OR_FRAGMENT = [
  'https://mcp.nutrihelp.test/mcp?x=1',
  'https://mcp.nutrihelp.test/mcp?x',
  'https://mcp.nutrihelp.test/mcp#frag',
  'https://mcp.nutrihelp.test/mcp?a=1#frag',
  'https://mcp.nutrihelp.test/mcp?',
  'https://mcp.nutrihelp.test/mcp#',
] as const;

/**
 * Ports outside the range, and values that are not numbers at all.
 *
 * The last four are the ones that need a digits-only test before the parse. A radix-10 integer
 * parse stops at the first character it cannot use, so `3.5`, `1e3` and `3000abc` come back as 3, 1
 * and 3000 — all inside the valid range, so a range check alone accepts every one of them and the
 * service listens on a port nobody configured, looks healthy and answers nothing. (`0x10` is
 * refused either way, since a base-10 parse reads it as 0; it is here because hex is a plausible
 * thing for an operator to write, not because it discriminates.)
 */
const REFUSED_PORTS = [
  '0',
  '-1',
  '65536',
  '99999',
  'abc',
  'NaN',
  'Infinity',
  '3.5',
  '1e3',
  '3000abc',
  '0x10',
] as const;

/** The boundaries plus the trimmed form, so the refusals above are not met by refusing everything. */
const ACCEPTED_PORTS = [
  { value: '1', port: 1 },
  { value: '65535', port: 65535 },
  { value: ' 8080 ', port: 8080 },
] as const;

/** Lists that parse to no origin at all. */
const EMPTY_ORIGIN_LISTS = [',', ' , ', ',,,'] as const;

/** Entries that are not origins. The allowlist is explicit origins, never a pattern. */
const INVALID_ORIGINS = ['claude.ai', 'not-a-url', 'https://', '*.claude.ai'] as const;

/** Every value that is present but not a value: an empty variable in a deployment environment is
 *  the common shape of a missing one, and a trailing newline is invisible in a dashboard. */
const BLANK_VALUES = ['', ' ', '   ', '\n', '\t', ' \n '] as const;

const saved = new Map<string, string | undefined>();

/**
 * `Reflect.deleteProperty` rather than `delete process.env[name]`: the variable name is computed
 * from the table, and assigning `undefined` would set the literal string "undefined" instead of
 * unsetting anything — which is a present value, and would make every absent-variable case below
 * assert the wrong thing.
 */
function unset(name: string): void {
  Reflect.deleteProperty(process.env, name);
}

function set(name: string, value: string | undefined): void {
  if (!saved.has(name)) saved.set(name, process.env[name]);
  if (value === undefined) unset(name);
  else process.env[name] = value;
}

beforeEach(() => {
  saved.clear();
  for (const name of REQUIRED_VARS) set(name, VALID[name]);
});

afterEach(() => {
  for (const [name, value] of saved) {
    if (value === undefined) unset(name);
    else process.env[name] = value;
  }
  saved.clear();
});

describe('the complete valid configuration', () => {
  /**
   * The anti-vacuity case, and it comes first on purpose: a loader hard-wired to throw satisfies
   * every refusal assertion in this file. Nothing below means anything without this.
   */
  it('loads', () => {
    const config = loadConfig();

    expect(config.port).toBe(3000);
    expect(config.allowedOriginHostnames).toEqual(['claude.ai']);
    expect(config.jwksUrl.href).toBe(MCP_JWKS_URL);
    expect(config.expectedIssuer).toBe(MCP_EXPECTED_ISSUER);
    expect(config.authServerUrl).toBe(MCP_AUTH_SERVER_URL);
    expect(config.resourceIdentifier).toBe(MCP_RESOURCE_IDENTIFIER);
    expect(
      config.jwksCacheMaxAgeMs,
      'configured in seconds and stored in milliseconds: the conversion is the one place this value can be wrong by a factor of a thousand, which is a revocation gap in one direction and a request storm at the authorization server in the other'
    ).toBe(600_000);
    expect(
      config.requestDeadlineMs,
      'already milliseconds, so it is stored as configured — the name carries the unit precisely so that nobody converts it twice'
    ).toBe(30_000);
  });

  it('takes hostnames only, because the Origin guard is port-agnostic', () => {
    set('MCP_ALLOWED_ORIGINS', 'https://claude.ai:8443, https://claude.com');

    expect(loadConfig().allowedOriginHostnames).toEqual(['claude.ai', 'claude.com']);
  });

  it('does not carry the same hostname twice', () => {
    set('MCP_ALLOWED_ORIGINS', 'https://claude.ai,https://claude.ai:443,http://claude.ai');

    expect(loadConfig().allowedOriginHostnames).toEqual(['claude.ai']);
  });
});

describe('a required variable that is absent or blank', () => {
  it.each(REQUIRED_VARS)('refuses to start when %s is absent', (name) => {
    set(name, undefined);

    expect(
      () => loadConfig(),
      `${name} has no default and no safe fallback: a server that boots without it accepts something it cannot check`
    ).toThrow(/PORT|MCP_/);
  });

  it.each(REQUIRED_VARS)('names %s in the failure, so an operator knows which one', (name) => {
    set(name, undefined);

    expect(() => loadConfig()).toThrow(new RegExp(name));
  });

  it.each(REQUIRED_VARS.flatMap((name) => BLANK_VALUES.map((value) => ({ name, value }))))(
    'refuses to start when $name is present but blank',
    ({ name, value }) => {
      set(name, value);

      expect(
        () => loadConfig(),
        'a variable set to whitespace is the deployment-time shape of a missing one, and must not be treated as supplied'
      ).toThrow();
    }
  );

  /** `it.each([])` registers nothing and exits 0, so a table losing its rows would go quiet
   *  rather than red. */
  it('keeps a floor under the required-variable and blank-value tables', () => {
    expect(
      REQUIRED_VARS.length,
      'anti-vacuity: dropping a variable from the required set makes it optional in silence'
    ).toBeGreaterThanOrEqual(7);
    expect(BLANK_VALUES.length).toBeGreaterThanOrEqual(6);
  });
});

describe('a URL-valued variable over cleartext or a non-network scheme', () => {
  /**
   * Both URL variables go through the same scheme check, and the reason is not stylistic. A key
   * set fetched over cleartext can be substituted by anyone on the path, and every token minted
   * with the substituted key then satisfies the algorithm, issuer, audience and type pins because
   * the attacker chose all four. The resource identifier is no safer: the challenge pointer is
   * derived from its origin, so a cleartext identifier publishes a cleartext pointer.
   */
  const REFUSED_SCHEMES = [
    {
      label: 'http',
      jwks: 'http://auth.nutrihelp.test/jwks.json',
      resource: 'http://mcp.nutrihelp.test/mcp',
    },
    { label: 'file', jwks: 'file:///etc/jwks.json', resource: 'file:///mcp' },
    { label: 'data', jwks: 'data:application/json,{"keys":[]}', resource: 'data:text/plain,/mcp' },
  ] as const;

  it.each(REFUSED_SCHEMES)('refuses MCP_JWKS_URL over $label', ({ jwks }) => {
    set('MCP_JWKS_URL', jwks);

    expect(() => loadConfig()).toThrow(/https/);
  });

  it.each(REFUSED_SCHEMES)('refuses MCP_RESOURCE_IDENTIFIER over $label', ({ resource }) => {
    set('MCP_RESOURCE_IDENTIFIER', resource);

    expect(
      () => loadConfig(),
      'the identifier is refused for the same reason as the key set, one hop further out: substituting the document its pointer names moves the client to an authorization server of the attacker choosing'
    ).toThrow(/https/);
  });

  it.each(URL_VARS)('refuses %s when it is not an absolute URL', (name) => {
    set(name, '/mcp');

    expect(() => loadConfig()).toThrow(/absolute URL/);
  });

  it('keeps a floor under the refused-scheme table', () => {
    expect(REFUSED_SCHEMES.length).toBeGreaterThanOrEqual(3);
    expect(URL_VARS.length).toBe(3);
  });
});

describe('the resource identifier, which is also the expected audience', () => {
  it.each(NO_RESOURCE_PATH)('refuses %s, which carries no resource path', (value) => {
    set('MCP_RESOURCE_IDENTIFIER', value);

    expect(
      () => loadConfig(),
      'the identifier includes the path, and a bare origin would publish a pointer at a location the document does not live'
    ).toThrow(/resource path/);
  });

  /**
   * A query string or a fragment is refused, whether or not it carries content. The pointer is
   * built from origin and path alone, so either one would be dropped from the published pointer
   * while the audience comparison kept it — and the bare forms are the ones a parsed test cannot
   * see, since `search` and `hash` are empty for both while `href` keeps the character.
   */
  it.each(
    PUBLISHED_IDENTIFIER_VARS.flatMap((name) =>
      WITH_USERINFO.map((value) => [name, value] as const)
    )
  )('%s refuses %s, which would publish a credential to unauthenticated callers', (name, value) => {
    set(name, value);

    expect(() => loadConfig()).toThrow(/userinfo/);
  });

  it.each(
    PUBLISHED_IDENTIFIER_VARS.flatMap((name) =>
      QUERY_OR_FRAGMENT.map((value) => [name, value] as const)
    )
  )('%s refuses %s', (name, value) => {
    set(name, value);

    expect(() => loadConfig()).toThrow(/query string|fragment/);
  });

  it('keeps a floor under the published-identifier pair', () => {
    expect(PUBLISHED_IDENTIFIER_VARS.length).toBe(2);
    expect(WITH_USERINFO.length).toBeGreaterThanOrEqual(2);
    expect(QUERY_OR_FRAGMENT.length).toBeGreaterThanOrEqual(6);
  });

  it.each(ROUTE_METACHARACTER_PATHS)(
    'refuses %s, whose path Express would re-read as a route pattern',
    (value) => {
      set('MCP_RESOURCE_IDENTIFIER', value);

      expect(() => loadConfig()).toThrow(/route-pattern metacharacter/);
    }
  );

  /**
   * The normalisation that makes the audience and the derived pointer agree. Without it an
   * identifier differing only in host case publishes one spelling while the audience check demands
   * another, and the failure surfaces as a client discarding the metadata document.
   */
  it('normalises host case so the audience and the pointer cannot disagree', () => {
    set('MCP_RESOURCE_IDENTIFIER', 'https://MCP.NutriHelp.TEST/mcp');

    const { resourceIdentifier } = loadConfig();

    expect(resourceIdentifier, 'the normalised form is stored, not the raw value').toBe(
      'https://mcp.nutrihelp.test/mcp'
    );
    expect(
      protectedResourceMetadataUrl(resourceIdentifier),
      'the pointer derived from the stored identifier must name the document the deployment publishes'
    ).toBe('https://mcp.nutrihelp.test/.well-known/oauth-protected-resource/mcp');
  });

  it('normalises a default port away rather than storing two spellings of one audience', () => {
    set('MCP_RESOURCE_IDENTIFIER', 'https://mcp.nutrihelp.test:443/mcp');

    expect(loadConfig().resourceIdentifier).toBe('https://mcp.nutrihelp.test/mcp');
  });

  it('trims surrounding whitespace, which is invisible in a deployment dashboard', () => {
    set('MCP_RESOURCE_IDENTIFIER', `  ${MCP_RESOURCE_IDENTIFIER}\n`);

    expect(
      loadConfig().resourceIdentifier,
      'an audience is compared byte for byte, and a trailing newline in a service variable cannot be seen'
    ).toBe(MCP_RESOURCE_IDENTIFIER);
  });

  it('keeps a floor under the resource-identifier tables', () => {
    expect(NO_RESOURCE_PATH.length).toBeGreaterThanOrEqual(2);
    expect(
      QUERY_OR_FRAGMENT.length,
      'the two bare-delimiter rows are the only ones a parsed-field check does not already refuse: drop them and the raw-string test is unheld'
    ).toBeGreaterThanOrEqual(6);
    expect(WITH_USERINFO.length).toBeGreaterThanOrEqual(2);
  });
});

describe('PORT', () => {
  it.each(REFUSED_PORTS)('refuses %s', (value) => {
    set('PORT', value);

    expect(() => loadConfig()).toThrow(/PORT/);
  });

  it.each(ACCEPTED_PORTS)('accepts $value', ({ value, port }) => {
    set('PORT', value);

    expect(loadConfig().port).toBe(port);
  });

  it('keeps a floor under both PORT tables', () => {
    expect(
      REFUSED_PORTS.length,
      'the four partially-numeric rows are the whole reason the loader tests for digits before parsing: drop them and a range check alone passes this block'
    ).toBeGreaterThanOrEqual(11);
    expect(
      ACCEPTED_PORTS.length,
      'anti-vacuity: with no accepted ports, a loader that refuses every port passes this describe block'
    ).toBeGreaterThanOrEqual(3);
  });
});

describe('the whole-number variables share one guard', () => {
  it.each(
    WHOLE_NUMBER_VARS.flatMap((name) => REFUSED_WHOLE_NUMBERS.map((value) => ({ name, value })))
  )('refuses $name set to $value', ({ name, value }) => {
    set(name, value);

    expect(
      () => loadConfig(),
      'a value that is not wholly digits is refused rather than truncated: the helper is shared, and a variable that grew its own parse would be the one place a partial number is taken silently'
    ).toThrow(new RegExp(name));
  });

  it('keeps a floor under the shared refusal table', () => {
    expect(REFUSED_WHOLE_NUMBERS.length).toBeGreaterThanOrEqual(8);
    expect(
      WHOLE_NUMBER_VARS.length,
      'both non-PORT numeric variables go through the table above, or one of them is asserted only by the fixture loading'
    ).toBe(2);
  });
});

/**
 * The key-set lifetime, whose floor is the only bound here that encodes a decision rather than a
 * sanity limit.
 *
 * **It is an amplification bound, not a taste bound.** The verification library refetches the key set
 * whenever the copy it holds is older than this lifetime, and the cooldown that limits its
 * unknown-key retry does not gate that path — so a lifetime shorter than the interval between inbound
 * requests turns every inbound MCP request into an outbound one against the authorization server,
 * each spending the whole request budget. That is the denial-of-service vector aimed at the
 * authorization server which this variable exists to let an operator avoid, and it is reachable from
 * a value the verification library itself would call perfectly legal.
 */
describe('the key-set lifetime floor', () => {
  /** Below the floor, and `59` is the one that matters: it is a number an operator would plausibly
   *  write, it parses cleanly, and nothing but the floor refuses it. */
  const BELOW_THE_FLOOR = ['0', '1', '30', '59'] as const;

  /** Truncations that land at or above the floor, so only the digits-only test refuses them. Without
   *  it `60abc` reads as 60 and `600.5` as 600 — both legal lifetimes nobody configured. */
  const TRUNCATES_INTO_RANGE = ['60abc', '600.5', '3600zz'] as const;

  it.each(BELOW_THE_FLOOR)('refuses a lifetime of %s seconds', (value) => {
    set('MCP_JWKS_CACHE_TTL_S', value);

    expect(
      () => loadConfig(),
      'a lifetime under the floor makes one inbound request one outbound request to the authorization server, which is the amplification this bound exists to prevent'
    ).toThrow(/MCP_JWKS_CACHE_TTL_S/);
  });

  it.each(TRUNCATES_INTO_RANGE)('refuses %s rather than truncating it into range', (value) => {
    set('MCP_JWKS_CACHE_TTL_S', value);

    expect(() => loadConfig()).toThrow(/MCP_JWKS_CACHE_TTL_S/);
  });

  /**
   * A ceiling exists. **Where it sits is deliberately not asserted**, because it is not a number the
   * plan owns — the loader calls its upper bounds sanity limits rather than policy, and the plan
   * fixes only the floor. Pinning the exact ceiling here would turn a later decision about revocation
   * gaps into a red test that someone "fixes" by editing this line.
   *
   * So the value is far outside any lifetime a reviewer would plausibly choose: it asserts that an
   * absurd value is refused, and survives the ceiling being set anywhere reasonable.
   */
  it('refuses an absurd lifetime, so some ceiling is in force', () => {
    set('MCP_JWKS_CACHE_TTL_S', '99999999');

    expect(() => loadConfig()).toThrow(/MCP_JWKS_CACHE_TTL_S/);
  });

  /**
   * The anti-vacuity half, and without it a loader that refused every lifetime would satisfy every
   * assertion above. The floor value itself is the case that matters: it is the boundary, so a guard
   * written with the wrong comparison refuses it.
   */
  it.each([
    { value: '60', ms: 60_000 },
    { value: '3600', ms: 3_600_000 },
    { value: ' 900 ', ms: 900_000 },
  ])('accepts $value and stores it as milliseconds', ({ value, ms }) => {
    set('MCP_JWKS_CACHE_TTL_S', value);

    expect(
      loadConfig().jwksCacheMaxAgeMs,
      'the floor value is legal, and it is stored in milliseconds rather than the seconds it was written in'
    ).toBe(ms);
  });

  it('keeps a floor under the lifetime tables', () => {
    expect(BELOW_THE_FLOOR.length).toBeGreaterThanOrEqual(4);
    expect(TRUNCATES_INTO_RANGE.length).toBeGreaterThanOrEqual(3);
  });
});

describe('the request deadline', () => {
  /** Truncations that land inside the deadline's range, which starts at 1 — so all three of these are
   *  accepted by a parse without the digits-only test in front of it. */
  const TRUNCATES_INTO_RANGE = ['10.5', '1e3', '60abc'] as const;

  it.each(TRUNCATES_INTO_RANGE)('refuses %s rather than truncating it into range', (value) => {
    set('MCP_REQUEST_DEADLINE_MS', value);

    expect(
      () => loadConfig(),
      'a deadline nobody configured is worse than a missing one: the request budget would look set and be wrong, and every stage ceiling is assigned inside it'
    ).toThrow(/MCP_REQUEST_DEADLINE_MS/);
  });

  /** As above: that a floor and a ceiling exist is the property. Neither number is one the plan
   *  states, so the values are chosen to be obviously outside any range a reviewer would pick. */
  it.each(['0', '99999999'])('refuses %s, so a range is in force', (value) => {
    set('MCP_REQUEST_DEADLINE_MS', value);

    expect(() => loadConfig()).toThrow(/MCP_REQUEST_DEADLINE_MS/);
  });

  /** Anti-vacuity: the boundaries load, so the refusals above are not met by refusing everything. */
  it.each([
    { value: '5000', ms: 5_000 },
    { value: '120000', ms: 120_000 },
    { value: ' 30000 ', ms: 30_000 },
  ])('accepts $value', ({ value, ms }) => {
    set('MCP_REQUEST_DEADLINE_MS', value);

    expect(
      loadConfig().requestDeadlineMs,
      'stored exactly as configured: it is already milliseconds, and a second conversion here would be the factor-of-a-thousand defect the key-set lifetime has to guard against'
    ).toBe(ms);
  });

  it('keeps a floor under the deadline table', () => {
    expect(TRUNCATES_INTO_RANGE.length).toBeGreaterThanOrEqual(3);
  });
});

/** Both https-pinned. Only the resource identifier is normalised — issuer is compared byte-for-byte to a claim someone else mints. */
describe('the expected issuer', () => {
  it.each(['http://auth.nutrihelp.test', 'file:///issuer', 'data:text/plain,issuer'])(
    'refuses %s, because a substituted key set satisfies every other pin',
    (value) => {
      set('MCP_EXPECTED_ISSUER', value);

      expect(() => loadConfig()).toThrow(/https/);
    }
  );

  it('refuses a value that is not an absolute URL', () => {
    set('MCP_EXPECTED_ISSUER', 'auth.nutrihelp.test');

    expect(() => loadConfig()).toThrow(/absolute URL/);
  });

  it.each([
    'https://auth.nutrihelp.test',
    'https://auth.nutrihelp.test/',
    'https://auth.nutrihelp.test/oauth',
    'https://AUTH.NutriHelp.test',
  ])('stores %s verbatim, never normalised', (value) => {
    set('MCP_EXPECTED_ISSUER', value);

    expect(
      loadConfig().expectedIssuer,
      'the authorization server mints the iss claim and nothing obliges it to echo a spelling this server chose, so any normalisation here rejects every token from a server that writes it differently — a trailing slash appended by the URL parser is the common case and it is a total outage'
    ).toBe(value);
  });

  it('normalises the resource identifier while leaving the issuer alone, from one shared value', () => {
    const unslashedOrigin = 'https://mcp.nutrihelp.test';
    set('MCP_EXPECTED_ISSUER', unslashedOrigin);
    set('MCP_RESOURCE_IDENTIFIER', `${unslashedOrigin}/mcp`);

    const config = loadConfig();

    expect(config.expectedIssuer, 'verbatim').toBe(unslashedOrigin);
    expect(
      config.resourceIdentifier,
      'and normalised, so the two are demonstrably not sharing one treatment: this is the asymmetry, asserted rather than described'
    ).toBe(`${unslashedOrigin}/mcp`);
    expect(
      protectedResourceMetadataUrl(config.resourceIdentifier),
      'the pointer derives from the normalised identifier, which is why that one has to be normalised'
    ).toBe('https://mcp.nutrihelp.test/.well-known/oauth-protected-resource/mcp');
  });
});

describe('the allowed-origin list', () => {
  it.each(EMPTY_ORIGIN_LISTS)('refuses %s, which lists no origin', (value) => {
    set('MCP_ALLOWED_ORIGINS', value);

    expect(() => loadConfig()).toThrow(/MCP_ALLOWED_ORIGINS/);
  });

  it.each(INVALID_ORIGINS)('refuses %s, which is not a valid origin', (value) => {
    set('MCP_ALLOWED_ORIGINS', value);

    expect(
      () => loadConfig(),
      'the allowlist is explicit origins, never a pattern, and an entry that cannot be parsed cannot be matched'
    ).toThrow(/MCP_ALLOWED_ORIGINS/);
  });

  it('refuses the whole list when any single entry is invalid', () => {
    set('MCP_ALLOWED_ORIGINS', `${ALLOWED_ORIGIN},*.vercel.app`);

    expect(
      () => loadConfig(),
      'a partially valid list must not load with the bad entry quietly dropped: the operator asked for something the server cannot honour'
    ).toThrow(/MCP_ALLOWED_ORIGINS/);
  });

  it('keeps a floor under the origin-list tables', () => {
    expect(EMPTY_ORIGIN_LISTS.length).toBeGreaterThanOrEqual(3);
    expect(INVALID_ORIGINS.length).toBeGreaterThanOrEqual(4);
  });
});

/**
 * Scoped to the two GENERIC helpers, deliberately. `required` and the URL helpers are the ones the
 * next variable goes through, and the next variable may be a private key.
 *
 * Two variable-specific messages DO echo their rejected value — the PORT range message and the
 * allowed-origin entry message. Both values are non-secret by inspection, so neither is a finding;
 * naming them here is what stops this describe block reading as a blanket certification it does not
 * hold.
 */
describe('what the generic startup helpers are allowed to say', () => {
  it('does not echo the rejected value of a URL variable', () => {
    const secretish = 'http://auth.nutrihelp.test/jwks.json?token=super-secret-value';
    set('MCP_JWKS_URL', secretish);

    expect(() => loadConfig()).toThrow(/MCP_JWKS_URL/);
    try {
      loadConfig();
      expect.unreachable('the cleartext scheme must be refused');
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message, 'the variable name and the constraint, never the value').not.toContain(
        'super-secret-value'
      );
    }
  });

  it('does not echo the rejected value of an absent variable', () => {
    set('MCP_EXPECTED_ISSUER', undefined);

    try {
      loadConfig();
      expect.unreachable('an absent issuer must be refused');
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      expect(message).toContain('MCP_EXPECTED_ISSUER');
      expect(message.toLowerCase()).toContain('missing');
    }
  });
});
