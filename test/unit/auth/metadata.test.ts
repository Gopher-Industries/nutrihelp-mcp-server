/** Protected resource metadata document and route derivation. */

import { describe, expect, it } from 'vitest';
import {
  protectedResourceMetadata,
  protectedResourceMetadataPaths,
} from '../../../src/auth/metadata.ts';
import { protectedResourceMetadataUrl } from '../../../src/auth/challenge.ts';
import { MCP_AUTH_SERVER_URL, MCP_RESOURCE_IDENTIFIER } from '../../support/testEnv.ts';

/**
 * Everything this document is allowed to carry. A closed set rather than a list of absences:
 * asserting that today's four unwanted keys are missing says nothing about the fifth.
 */
const PERMITTED_KEYS = ['resource', 'authorization_servers', 'bearer_methods_supported'];

/** RFC 8414 fields — belong on the backend authorization-server document, not here. */
const AUTHORIZATION_SERVER_FIELDS = [
  'code_challenge_methods_supported',
  'client_id_metadata_document_supported',
  'token_endpoint_auth_methods_supported',
  'token_endpoint',
  'authorization_endpoint',
  'registration_endpoint',
  'jwks_uri',
];

function document(): Record<string, unknown> {
  return protectedResourceMetadata({
    resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
    authorizationServers: [MCP_AUTH_SERVER_URL],
  }) as unknown as Record<string, unknown>;
}

describe('the protected resource metadata document', () => {
  it('echoes the configured resource identifier byte for byte', () => {
    expect(
      document().resource,
      'a client discards a document whose `resource` is not the exact string it asked about, so this is echoed rather than reassembled from origin and path'
    ).toBe(MCP_RESOURCE_IDENTIFIER);
  });

  it('names the authorization server a client must start the connect flow against', () => {
    expect(document().authorization_servers).toStrictEqual([MCP_AUTH_SERVER_URL]);
  });

  it('advertises only the credential placement the transport actually reads', () => {
    expect(
      document().bearer_methods_supported,
      'the transport reads the credential from the Authorization header and from nowhere else. Advertising `body` or `query` would describe a server that does not exist'
    ).toStrictEqual(['header']);
  });

  it('carries no authorization-server field, because it is not that document', () => {
    const keys = Object.keys(document());
    for (const field of AUTHORIZATION_SERVER_FIELDS) {
      expect(
        keys,
        `${field} belongs to the RFC 8414 document the backend publishes. Advertising it here claims a property this server neither owns nor can honour`
      ).not.toContain(field);
    }
  });

  it('carries nothing outside the permitted set, so a later addition is a decision', () => {
    expect(
      Object.keys(document()).sort(),
      'a closed set rather than a list of absences: naming the fields we do not want says nothing about the next one someone adds'
    ).toStrictEqual([...PERMITTED_KEYS].sort());
  });

  it('does not advertise scopes while no scope is enforced', () => {
    expect(
      Object.keys(document()),
      'scopes_supported is optional, and a scope list nothing checks is a claim the code cannot back. It arms with the tool-to-scope map'
    ).not.toContain('scopes_supported');
  });

  it('refuses to build a document that names no authorization server', () => {
    expect(() =>
      protectedResourceMetadata({
        resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
        authorizationServers: [],
      })
    ).toThrow(/authorization server/i);
  });

  it('copies the authorization server list, so a later mutation cannot reach the document', () => {
    const servers = [MCP_AUTH_SERVER_URL];
    const built = protectedResourceMetadata({
      resourceIdentifier: MCP_RESOURCE_IDENTIFIER,
      authorizationServers: servers,
    });
    servers.push('https://attacker.test');

    expect(
      built.authorization_servers,
      'the document is built once at startup and served for the life of the process'
    ).toStrictEqual([MCP_AUTH_SERVER_URL]);
  });
});

describe('where the document is served', () => {
  it('serves the primary document at exactly the path the challenge pointer names', () => {
    const pointer = new URL(protectedResourceMetadataUrl(MCP_RESOURCE_IDENTIFIER));

    expect(
      protectedResourceMetadataPaths(MCP_RESOURCE_IDENTIFIER).primary,
      'the pointer and the route come from one derivation. Two hand-written copies of one location read complete on their own and disagree in the direction nobody tests'
    ).toBe(pointer.pathname);
  });

  it('inserts the well-known segment ahead of the resource path', () => {
    expect(protectedResourceMetadataPaths(MCP_RESOURCE_IDENTIFIER).primary).toBe(
      '/.well-known/oauth-protected-resource/mcp'
    );
  });

  it('also answers the root probe some clients use instead', () => {
    expect(protectedResourceMetadataPaths(MCP_RESOURCE_IDENTIFIER).rootProbe).toBe(
      '/.well-known/oauth-protected-resource'
    );
  });

  it('tracks the resource path rather than hardcoding one', () => {
    expect(
      protectedResourceMetadataPaths('https://other.test/deep/resource').primary,
      'control: a derivation that ignored its input would return the fixture path here and every assertion above would still pass'
    ).toBe('/.well-known/oauth-protected-resource/deep/resource');
  });
});
