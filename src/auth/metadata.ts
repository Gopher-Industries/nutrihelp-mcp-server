/**
 * Protected resource metadata (RFC 9728), generated from configuration.
 * Not the RFC 8414 authorization-server document — those fields belong on the backend.
 */

import { protectedResourceMetadataUrl } from './challenge.ts';

export interface ProtectedResourceMetadataOptions {
  /** The canonical, normalised resource identifier. Also this server's expected audience. */
  readonly resourceIdentifier: string;
  /** Issuer identifiers of the authorization servers that mint tokens for this resource. */
  readonly authorizationServers: readonly string[];
}

export interface ProtectedResourceMetadata {
  readonly resource: string;
  readonly authorization_servers: readonly string[];
  readonly bearer_methods_supported: readonly string[];
}

const BEARER_METHODS_SUPPORTED = ['header'] as const;

/** `scopes_supported` omitted until the tool-to-scope map exists. */
export function protectedResourceMetadata(
  options: ProtectedResourceMetadataOptions
): ProtectedResourceMetadata {
  if (options.authorizationServers.length === 0) {
    throw new Error(
      'protected resource metadata needs at least one authorization server, or a client that reads it cannot start the connect flow'
    );
  }
  return {
    resource: options.resourceIdentifier,
    authorization_servers: [...options.authorizationServers],
    bearer_methods_supported: [...BEARER_METHODS_SUPPORTED],
  };
}

export interface MetadataPaths {
  /** Where the challenge pointer sends a client. */
  readonly primary: string;
  /** Same document, for clients that probe the root instead. Tolerated, not relied on. */
  readonly rootProbe: string;
}

/** The root probe. The primary path is this plus the resource's own path. */
const ROOT_PROBE_PATH = '/.well-known/oauth-protected-resource';

/** Pathnames derived from the same function as the challenge pointer. */
export function protectedResourceMetadataPaths(resourceIdentifier: string): MetadataPaths {
  return {
    primary: new URL(protectedResourceMetadataUrl(resourceIdentifier)).pathname,
    rootProbe: ROOT_PROBE_PATH,
  };
}
