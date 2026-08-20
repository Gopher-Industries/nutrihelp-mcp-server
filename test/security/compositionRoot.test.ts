/**
 * Source scan of `src/server.ts`: behavioural tests build their own app, so they cannot see a
 * deployed root wired on the unauthenticated opt-out.
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/** Literal, not imported — importing would stay green if the sentinel were renamed. */
const OPT_OUT_SENTINEL = 'transport-tests-only';

function sourceOf(relativePath: string): string {
  return readFileSync(new URL(`../../${relativePath}`, import.meta.url), 'utf8');
}

describe('the composition root', () => {
  it('never builds the transport on the unauthenticated opt-out', () => {
    const source = sourceOf('src/server.ts');

    expect(source).not.toContain(OPT_OUT_SENTINEL);
    // Property assignment, not the bare word — comments in server.ts mention unauthenticated fetches.
    expect(source).not.toMatch(/\bunauthenticated\s*:/);
  });

  it('finds the sentinel in the module that declares it', () => {
    const transport = sourceOf('src/transport/http.ts');

    expect(
      transport,
      'control: the declaring module carries the literal, so the absence above is a property of the composition root rather than of a scanner that reads nothing'
    ).toContain(OPT_OUT_SENTINEL);
    expect(
      transport.length,
      'control: and the file really was read rather than resolving to an empty string'
    ).toBeGreaterThan(1000);
  });

  it('does wire a validator and a metadata pointer into the endpoint it builds', () => {
    const source = sourceOf('src/server.ts');

    expect(
      source,
      'the endpoint is built with a validator. Anchored on the binding, not the bare property name: this file writes property names inside comments, so a looser pattern would be satisfied by prose'
    ).toMatch(/validator:\s*tokenValidator/);
    expect(
      source,
      'and it does NOT hand the transport a separate challenge pointer. That field was removed once the transport began deriving the pointer from the document it serves — re-adding it here would make "the pointer names somewhere the router does not answer" representable again, which is the whole failure this ticket closed'
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
