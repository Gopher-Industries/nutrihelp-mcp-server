/**
 * Source scan of `src/server.ts`: behavioural tests build their own app, so they cannot see a
 * deployed root wired on the unauthenticated opt-out.
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { AUTH_SERVER_ORIGIN, INTROSPECTION_PATH } from '../support/testEnv.ts';

/**
 * Literal, not imported — importing would stay green if the sentinel were renamed.
 * Shared by `unauthenticated` and `revocationDisabled`; property names are asserted separately
 * because a root could reach either opt-out via a constant this scan cannot follow.
 */
const OPT_OUT_SENTINEL = 'transport-tests-only';

function sourceOf(relativePath: string): string {
  return readFileSync(new URL(`../../${relativePath}`, import.meta.url), 'utf8');
}

/**
 * Arguments the root hands `createHttpApp`, nothing before. `resourceMetadataUrl` is forbidden
 * on the transport but required on the checker under the same name — whole-file scan cannot tell.
 */
function transportOptionsIn(source: string): string {
  const start = source.indexOf('createHttpApp(');
  expect(
    start,
    'control: the root builds the transport, or this scan reads nothing'
  ).toBeGreaterThan(-1);
  return source.slice(start);
}

/**
 * Hand-typed introspection path in the root vs `INTROSPECTION_PATH` in tests — two copies of one
 * value. Compared with `toBe`, never `toContain`: a suffix is exactly the drift a path suffers.
 */
function introspectionPathLiteralIn(source: string): string {
  const match = /new URL\(\s*(['"])([^'"]*)\1\s*,\s*config\.authServerUrl\s*\)/.exec(source);
  expect(
    match,
    'control: the root resolves a literal path against the configured authorization server. If this stops matching, the URL is being built some other way and this pin has stopped guarding anything — re-derive it rather than deleting it'
  ).not.toBeNull();
  return match?.[2] ?? '';
}

describe('the composition root', () => {
  it('never builds the transport on the unauthenticated opt-out', () => {
    const source = sourceOf('src/server.ts');

    expect(source).not.toContain(OPT_OUT_SENTINEL);
    // Property assignment, not the bare word — comments in server.ts mention unauthenticated fetches.
    expect(source).not.toMatch(/\bunauthenticated\s*:/);
  });

  /**
   * Same absence guard for live introspection. Behavioural tests build their own app, so they
   * cannot see a deployed root on this opt-out.
   */
  it('never builds the transport on the introspection opt-out', () => {
    const source = sourceOf('src/server.ts');

    expect(
      source,
      'the property assignment, not the bare word: a root that names this field has disabled the one check that makes disconnecting real'
    ).not.toMatch(/\brevocationDisabled\s*:/);
  });

  it('finds both sentinels in the module that declares them', () => {
    const transport = sourceOf('src/transport/http.ts');

    expect(
      transport,
      'control: the declaring module carries the literal, so the absence above is a property of the composition root rather than of a scanner that reads nothing'
    ).toContain(OPT_OUT_SENTINEL);
    expect(
      transport,
      'control: and it declares the unauthenticated opt-out under that name, so the absence assertion above is aimed at a property that exists'
    ).toMatch(/\bunauthenticated\s*:/);
    expect(
      transport,
      'control: and the introspection opt-out likewise. Renaming either field would otherwise leave this file green while asserting the absence of something nothing declares'
    ).toMatch(/\brevocationDisabled\s*:/);
    expect(
      transport.length,
      'control: and the file really was read rather than resolving to an empty string'
    ).toBeGreaterThan(1000);
  });

  /**
   * Granting half: absence alone is satisfied by a root that wires no authorization at all.
   */
  it('wires a real revocation checker, built from this server own registered client identifier', () => {
    const source = sourceOf('src/server.ts');

    expect(
      source,
      'the deployed root constructs the production checker. Anchored on the call rather than on a variable name, which is style rather than contract'
    ).toContain('createRevocationChecker(');
    expect(
      source,
      'and hands it to the transport as a value, not as an object literal — the only object literal that field accepts is the opt-out'
    ).toMatch(/revocation:\s*[A-Za-z_$]/);
    expect(
      source,
      'the assertion is signed as the client identifier the authorization server registered, read from configuration. A root passing config.resourceIdentifier here by adjacency would authenticate as the resource, which is the conflation the loader refuses to start on'
    ).toMatch(/clientId:\s*config\.clientId/);
    expect(
      source,
      'and it must NOT pass the resource identifier as the client identifier'
    ).not.toMatch(/clientId:\s*config\.resourceIdentifier/);
    expect(
      source,
      'the pointer the checker carries is DERIVED from the same configured identifier the served document is, so the two cannot name different locations. A literal here would be a second hand-maintained copy of one value'
    ).toMatch(/resourceMetadataUrl:\s*protectedResourceMetadataUrl\(config\.resourceIdentifier\)/);
    expect(
      source,
      'and the negative-cache lifetime comes from its own configured value. A literal here would be a lifetime nobody set, on the one knob whose whole point is that an operator can turn it off'
    ).toMatch(/negativeCacheMaxAgeMs:\s*config\.revokedGrantCacheMaxAgeMs/);
  });

  /**
   * The only checker arg written as a literal rather than config — a wrong path fails as a 404
   * that looks like the AS being down.
   */
  it('introspects against the one path the rest of the tree already names', () => {
    const source = sourceOf('src/server.ts');

    expect(
      introspectionPathLiteralIn(source),
      'the deployed server and every test must call one path. This is the one hand-written statement of it that is allowed to move, and changing the literal in the composition root alone has to go red here'
    ).toBe(INTROSPECTION_PATH);
    expect(
      source,
      'and the origin comes from configuration rather than a second literal: an absolute URL written out here would ignore the configured authorization server entirely'
    ).not.toMatch(/introspectionUrl:\s*['"]https:/);
  });

  /**
   * Leading-slash path is absolute: join against a base discards any path the base carried.
   * Correct at an origin-rooted AS; silent truncation under a path prefix. Asserted, not decided.
   */
  it('resolves that path against the authorization server origin, discarding any path the base carries', () => {
    const literal = introspectionPathLiteralIn(sourceOf('src/server.ts'));

    expect(
      literal.startsWith('/'),
      'a leading slash is what makes the resolution absolute, and it is also what makes the discard below happen'
    ).toBe(true);

    expect(
      new URL(literal, AUTH_SERVER_ORIGIN).href,
      'against an origin-rooted authorization server the join is exactly the endpoint every test mocks'
    ).toBe(`${AUTH_SERVER_ORIGIN}${INTROSPECTION_PATH}`);

    expect(
      new URL(literal, `${AUTH_SERVER_ORIGIN}/tenant/acme`).href,
      'and against one deployed under a path, that path is DROPPED rather than prefixed. Asserted rather than described: an authorization server at /tenant/acme would be introspected at the origin root, which answers 404, which surfaces as a retryable outage nobody can tell apart from the server being down'
    ).toBe(`${AUTH_SERVER_ORIGIN}${INTROSPECTION_PATH}`);
  });

  /**
   * Transport must receive the budget. Scoped: the validator takes the same field name.
   */
  it('gives the transport the configured end-to-end request budget', () => {
    const options = transportOptionsIn(sourceOf('src/server.ts'));

    expect(
      options,
      'a literal budget here is a deadline nobody configured, and every stage ceiling is assigned inside it'
    ).toMatch(/requestDeadlineMs:\s*config\.requestDeadlineMs/);
  });

  it('does wire a validator and a metadata pointer into the endpoint it builds', () => {
    const source = sourceOf('src/server.ts');

    expect(
      source,
      'the endpoint is built with a validator. Anchored on the binding, not the bare property name: this file writes property names inside comments, so a looser pattern would be satisfied by prose'
    ).toMatch(/validator:\s*tokenValidator/);
    expect(
      transportOptionsIn(source),
      'and it does NOT hand the transport a separate challenge pointer. That field was removed once the transport began deriving the pointer from the document it serves — re-adding it here would make "the pointer names somewhere the router does not answer" representable again, which is the whole failure this ticket closed. Scoped to the transport arguments: the revocation checker takes a field of the same name, and that one is required'
    ).not.toMatch(/resourceMetadataUrl\s*:/);
  });

  it('publishes the document that pointer resolves to, generated rather than written out here', () => {
    const source = sourceOf('src/server.ts');

    expect(
      source,
      'the deployed root serves the discovery document. Without it every challenge above points at a 404 and no conformant client gets past discovery'
    ).toMatch(/resourceMetadata:\s*protectedResourceMetadata\(/);
    expect(
      source,
      'and the document is fed the same identifier the pointer is derived from, so the two cannot disagree'
    ).toMatch(/resourceIdentifier:\s*config\.resourceIdentifier/);
    expect(
      source,
      'and the authorization server comes from its own config value. A root passing a literal, or passing config.expectedIssuer by adjacency, would satisfy every other assertion here — and those two values being confusable is exactly what the open question about them is about'
    ).toMatch(/authorizationServers:\s*\[config\.authServerUrl\]/);
  });
});
