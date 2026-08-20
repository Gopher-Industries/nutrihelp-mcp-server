/**
 * Unit suite for the Bearer challenge builders and the metadata pointer they carry.
 *
 * These functions are branch-free by design, which is exactly why they need their own file: the
 * 90% BRANCH gate on `src/auth/**` reports 100% for a module with no branches in it, so the gate
 * is satisfied by a module nothing has ever called. Branch coverage cannot see this file; only
 * these cases can.
 *
 * Every assertion is about the wire form a client parses, not about how the string is built.
 *
 * Hostile control characters are constructed by code point, never typed. A literal NUL, BEL or DEL
 * in a source file makes it a binary blob to git, grep and prettier at once.
 */

import { describe, expect, it } from 'vitest';
import {
  insufficientScopeChallenge,
  invalidTokenChallenge,
  protectedResourceMetadataUrl,
  safeInOneLine,
  unauthenticatedChallenge,
} from '../../../src/auth/challenge.ts';
import { MCP_RESOURCE_IDENTIFIER, RESOURCE_METADATA_URL, SCOPES } from '../../support/testEnv.ts';

interface ChallengeParam {
  readonly name: string;
  readonly value: string;
}

interface ParsedChallenge {
  readonly scheme: string;
  readonly params: readonly ChallengeParam[];
}

/**
 * Parse a `WWW-Authenticate` value the way a client does: a scheme, then comma-separated
 * `name=value` pairs where a value may be a quoted string.
 *
 * Scanning a quoted string as `"[^"]*"` is sound here only because the builders strip every quote
 * and backslash from a value first. That is the property under test, so the parser is deliberately
 * naive: if a value ever manages to carry a quote, this parser mis-splits it and the
 * exact-parameter-set assertions below go red. A parser that tolerated escapes would hide the bug.
 */
function parseChallenge(challenge: string): ParsedChallenge {
  const space = challenge.indexOf(' ');
  const scheme = space === -1 ? challenge : challenge.slice(0, space);
  const rest = space === -1 ? '' : challenge.slice(space + 1);

  const params: ChallengeParam[] = [];
  const pair = /([!#$%&'*+\-.^_`|~0-9A-Za-z]+)=(?:"([^"]*)"|([^",]*))/g;
  for (const match of rest.matchAll(pair)) {
    params.push({ name: match[1] ?? '', value: match[2] ?? match[3] ?? '' });
  }
  return { scheme, params };
}

function paramNames(challenge: string): string[] {
  return parseChallenge(challenge).params.map((param) => param.name);
}

function paramValue(challenge: string, name: string): string | undefined {
  return parseChallenge(challenge).params.find((param) => param.name === name)?.value;
}

describe('the protected resource metadata pointer', () => {
  it('is byte-identical to the published document location', () => {
    // Not "looks right": a pointer differing from the document's own `resource` value by one byte
    // is discarded by a conformant client, which presents as a connect flow that never starts
    // rather than as an error anyone can read.
    expect(
      protectedResourceMetadataUrl(MCP_RESOURCE_IDENTIFIER),
      'the challenge pointer and the fixture every challenge assertion compares against must be the same bytes'
    ).toBe(RESOURCE_METADATA_URL);
  });

  it('inserts the well-known segment between the origin and the resource path', () => {
    expect(protectedResourceMetadataUrl('https://mcp.example.test:8443/a/b')).toBe(
      'https://mcp.example.test:8443/.well-known/oauth-protected-resource/a/b'
    );
  });

  it('does not append the well-known segment to the path', () => {
    // The shape is origin + well-known + path, not path + well-known. The wrong order still
    // produces a plausible-looking URL, so pin it.
    const pointer = protectedResourceMetadataUrl(MCP_RESOURCE_IDENTIFIER);

    expect(pointer).not.toBe(`${MCP_RESOURCE_IDENTIFIER}/.well-known/oauth-protected-resource`);
    expect(pointer.startsWith('https://mcp.nutrihelp.test/.well-known/')).toBe(true);
  });
});

describe('the unauthenticated challenge', () => {
  const challenge = unauthenticatedChallenge(RESOURCE_METADATA_URL);

  it('uses the Bearer scheme', () => {
    expect(parseChallenge(challenge).scheme).toBe('Bearer');
  });

  it('carries resource_metadata and nothing else', () => {
    // The exact set, not a containment check. An `error` parameter here would tell a client that
    // sent no credential to correct one, and this response starts the connect flow rather than
    // rejecting anything.
    expect(
      paramNames(challenge),
      'a client that presented nothing has nothing to correct, so there is no error parameter'
    ).toEqual(['resource_metadata']);
  });

  it('names the metadata document', () => {
    expect(paramValue(challenge, 'resource_metadata')).toBe(RESOURCE_METADATA_URL);
  });
});

/**
 * Words that would name which check failed. A `for` loop over an empty list passes silently rather
 * than registering nothing, so this one needs a floor as much as an `it.each` table does.
 */
const DISCLOSURE_WORDS = [
  'expired',
  'expiry',
  'issuer',
  'audience',
  'signature',
  'algorithm',
  'claim',
  'kid',
  'revoked',
  'inactive',
  'introspect',
  'mismatch',
] as const;

describe('the invalid-token challenge', () => {
  const challenge = invalidTokenChallenge(RESOURCE_METADATA_URL);

  it('carries exactly error and resource_metadata', () => {
    expect(paramNames(challenge)).toEqual(['error', 'resource_metadata']);
    expect(paramValue(challenge, 'error')).toBe('invalid_token');
    expect(paramValue(challenge, 'resource_metadata')).toBe(RESOURCE_METADATA_URL);
  });

  /**
   * Which check failed is useful to someone probing the verifier and useless to a legitimate
   * client, whose response to every one of them is the same: refresh, or reauthorize.
   */
  it('never says which check failed', () => {
    // The pointer is removed first, so a word appearing inside the configured URL cannot fail
    // this assertion for a reason that has nothing to do with disclosure.
    const withoutPointer = challenge.replaceAll(RESOURCE_METADATA_URL, '<pointer>').toLowerCase();

    for (const disclosure of DISCLOSURE_WORDS) {
      expect(
        withoutPointer,
        `the invalid-token challenge must not disclose "${disclosure}": every verifier outcome looks the same to a client`
      ).not.toContain(disclosure);
    }
  });

  it('keeps a floor under the disclosure-word list', () => {
    expect(
      DISCLOSURE_WORDS.length,
      'anti-vacuity: emptying this list makes the assertion above pass over nothing, and a for loop does that silently rather than registering no tests'
    ).toBeGreaterThanOrEqual(12);
  });

  /** And the words are findable when present, so the absence result means "not there". */
  it('would catch a challenge that did disclose the reason', () => {
    const leaky = 'Bearer error="invalid_token", error_description="the token expired"';

    expect(
      DISCLOSURE_WORDS.some((word) => leaky.toLowerCase().includes(word)),
      'control: the word list must match a challenge that genuinely names a reason'
    ).toBe(true);
  });
});

describe('the insufficient-scope challenge', () => {
  const challenge = insufficientScopeChallenge(RESOURCE_METADATA_URL, SCOPES.meallogWrite);

  it('carries exactly error, scope and resource_metadata', () => {
    expect(paramNames(challenge)).toEqual(['error', 'scope', 'resource_metadata']);
  });

  it('names the required scope, which is what makes step-up possible', () => {
    expect(paramValue(challenge, 'error')).toBe('insufficient_scope');
    expect(paramValue(challenge, 'scope')).toBe(SCOPES.meallogWrite);
    expect(paramValue(challenge, 'resource_metadata')).toBe(RESOURCE_METADATA_URL);
  });

  it('does not claim the credential is invalid', () => {
    // A scope refusal that reads as a token problem sends the client into refresh-and-retry,
    // which mints the same scopes again and fails identically.
    expect(challenge).not.toContain('invalid_token');
  });
});

/**
 * `safeInOneLine` is one sanitiser for two readers with the same injection shape: a header
 * parameter value and a log line. A quote or a line break in either forges a second parameter or
 * a second entry.
 */
describe('sanitising a value that reaches a header and a log line', () => {
  /**
   * Built by code point rather than typed. A literal NUL, BEL or DEL in a source file makes the
   * file a binary blob to git, grep and prettier at once, and a literal non-ASCII letter depends
   * on the file's encoding surviving every tool that touches it. `\r` and `\n` stay as escapes
   * because those two are unambiguous everywhere.
   */
  const ch = (code: number): string => String.fromCharCode(code);
  const NUL = ch(0x00);
  const BEL = ch(0x07);
  const DEL = ch(0x7f);
  const E_ACUTE = ch(0xe9);
  const LINE_SEPARATOR = ch(0x2028);
  const RTL_OVERRIDE = ch(0x202e);
  const LONE_SURROGATE = ch(0xd800);

  /** Each row is a value an attacker would choose, paired with what it is trying to do. */
  const HOSTILE_VALUES: readonly { readonly label: string; readonly value: string }[] = [
    { label: 'a closing quote', value: 'nutrition:read"' },
    { label: 'a forged second parameter', value: 'nutrition:read", error="none' },
    { label: 'a backslash-escaped quote', value: 'nutrition:read\\"' },
    { label: 'a lone trailing backslash', value: 'nutrition:read\\' },
    { label: 'a carriage return', value: 'nutrition:read\r' },
    { label: 'a line feed', value: 'nutrition:read\n' },
    { label: 'a forged second header', value: 'nutrition:read\r\nWWW-Authenticate: Basic realm=x' },
    { label: 'a forged log entry', value: 'nutrition:read\n{"level":"info","msg":"all clear"}' },
    { label: 'a NUL', value: `nutrition:read${NUL}` },
    { label: 'a bell control character', value: `nutrition:read${BEL}` },
    { label: 'a DEL', value: `nutrition:read${DEL}` },
    { label: 'a non-ASCII letter', value: `nutrition:r${E_ACUTE}ad` },
    { label: 'a Unicode line separator', value: `nutrition:read${LINE_SEPARATOR}next` },
    { label: 'a right-to-left override', value: `nutrition:read${RTL_OVERRIDE}` },
    { label: 'a lone surrogate', value: `nutrition:read${LONE_SURROGATE}` },
  ];

  /** `it.each([])` registers nothing and still exits 0, so emptying the table above would make
   *  this whole describe block disappear in silence rather than go red. */
  it('keeps a floor under the hostile-value table', () => {
    expect(
      HOSTILE_VALUES.length,
      'anti-vacuity: deleting rows from the hostile-value table must fail this suite, not quieten it'
    ).toBeGreaterThanOrEqual(15);
  });

  it.each(HOSTILE_VALUES)('strips $label so it cannot close a quoted string', ({ value }) => {
    const sanitised = safeInOneLine(value);

    expect(sanitised, 'a quote closes the parameter value it sits in').not.toContain('"');
    expect(sanitised, 'a backslash is how a quote gets smuggled back in').not.toContain('\\');
    expect(sanitised, 'a CR starts a new header field').not.toMatch(/\r/);
    expect(sanitised, 'an LF starts a new header field and a new log entry').not.toMatch(/\n/);
    expect(sanitised, 'a NUL truncates in whatever reads the value next').not.toContain(NUL);
    expect(
      sanitised,
      'anything outside printable ASCII is dropped rather than escaped, so no reader has to agree with us about encoding'
    ).toMatch(/^[\x20-\x7e]*$/);
  });

  it.each(HOSTILE_VALUES)(
    'renders $label into a challenge that still has exactly three parameters',
    ({ value }) => {
      const challenge = insufficientScopeChallenge(RESOURCE_METADATA_URL, value);

      expect(
        paramNames(challenge),
        'a hostile scope value must not forge a fourth parameter and must not truncate the pointer away'
      ).toEqual(['error', 'scope', 'resource_metadata']);
      expect(challenge, 'the whole challenge is one header, on one line').not.toMatch(/[\r\n]/);
      expect(
        paramValue(challenge, 'resource_metadata'),
        'the pointer must survive intact: a client that cannot find the metadata document cannot ask for step-up'
      ).toBe(RESOURCE_METADATA_URL);
    }
  );

  it.each(HOSTILE_VALUES)('renders $label into a single-line log record', ({ value }) => {
    // The record shape the composition root writes. Asserted here rather than assumed, because
    // it is the same sanitiser and the same failure: a newline forges a whole entry.
    const line = JSON.stringify({
      level: 'error',
      msg: `insufficient_scope.${safeInOneLine(value)}`,
    });

    expect(line, 'one log record is one line').not.toMatch(/[\r\n]/);
    expect(
      line.split('\n'),
      'a forged second record would appear here as a second line'
    ).toHaveLength(1);
  });

  /**
   * The other direction, and the one the table above cannot prove: a sanitiser returning the empty
   * string for every input would satisfy every absence assertion in this file.
   */
  it('leaves an ordinary value untouched', () => {
    for (const scope of Object.values(SCOPES)) {
      expect(
        safeInOneLine(scope),
        'anti-vacuity: a sanitiser that empties everything passes every assertion above. A real scope name must survive verbatim'
      ).toBe(scope);
    }

    expect(safeInOneLine(RESOURCE_METADATA_URL)).toBe(RESOURCE_METADATA_URL);
    expect(safeInOneLine('nutrition:read'), 'a colon is printable ASCII and is kept').toBe(
      'nutrition:read'
    );
  });
});
