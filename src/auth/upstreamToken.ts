/**
 * This server's own credential at the authorization server.
 * PARTIAL: `private_key_jwt` assertion only. RFC 8693 exchange and credential cache belong
 * here later; their absence is not a decision that they live elsewhere.
 * Proves key possession; carries no user identity and mints nothing alone.
 */

import { SignJWT } from 'jose';
import type { KeyObject } from 'node:crypto';

/**
 * Signing algorithm per key type. Pinned, never negotiated. Absent types are refused.
 * `rsa-pss` is deliberately absent: Node cannot sign it here (`Invalid key type`), so a row
 * would name an algorithm that can never produce a signature. Plain `rsa` signs `RS256`.
 */
const ALGORITHM_BY_KEY_TYPE: Readonly<Record<string, string>> = {
  rsa: 'RS256',
  ec: 'ES256',
  ed25519: 'EdDSA',
};

/** Short because replayable within its window; long enough for clock skew. */
export const CLIENT_ASSERTION_LIFETIME_SECONDS = 60;

/** RFC 7521. The value the endpoint expects alongside `client_assertion`. */
export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export interface ClientAssertionRequest {
  /** This server's private key. Never logged, never serialised. */
  readonly key: KeyObject;
  /**
   * Registered client id at the authorization server (also the key-lookup id).
   * Required; no fallback. Not the resource identifier: separate registrations.
   * Until that id is configured, composition has nothing to pass (intended).
   */
  readonly clientId: string;
  /** Who must accept it: the endpoint being called. Introspection and exchange may differ. */
  readonly audience: string;
  /** Injected so expiry is testable without waiting. `undefined` takes the real clock. */
  readonly now: Date | undefined;
  /** Injected so replay assertions can pin it. `undefined` mints one. */
  readonly jti: string | undefined;
}

/** Blank is the shape an invented default arrives in, so it is refused loudly. */
function requireNonBlank(value: string, what: string): string {
  const trimmed = value.trim();
  if (trimmed === '') {
    throw new TypeError(
      `${what} must be a non-empty value. It is not defaulted and must not be derived from the ` +
        'resource identifier: they are separate registrations at the authorization server.'
    );
  }
  return trimmed;
}

function algorithmFor(key: KeyObject): string {
  const keyType = key.asymmetricKeyType;
  if (keyType === undefined) {
    throw new TypeError(
      'The client assertion key must be asymmetric. A symmetric secret would mean sharing a ' +
        'secret with the authorization server rather than proving possession of a key.'
    );
  }
  const algorithm = ALGORITHM_BY_KEY_TYPE[keyType];
  if (algorithm === undefined) {
    throw new TypeError(
      `No signing algorithm is pinned for key type "${keyType}". Add one deliberately, with a ` +
        'test that it can actually sign, rather than letting the key select it.'
    );
  }
  return algorithm;
}

/**
 * Build a `private_key_jwt` client assertion (RFC 7523).
 * `iss` and `sub` are both the client id: required by the spec, not a copy-paste.
 */
export async function clientAssertion(request: ClientAssertionRequest): Promise<string> {
  const clientId = requireNonBlank(request.clientId, 'The client assertion clientId');
  const audience = requireNonBlank(request.audience, 'The client assertion audience');
  const algorithm = algorithmFor(request.key);

  const issuedAt = Math.floor((request.now?.getTime() ?? Date.now()) / 1000);

  return new SignJWT({})
    .setProtectedHeader({ alg: algorithm, typ: 'JWT' })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setJti(request.jti ?? crypto.randomUUID())
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + CLIENT_ASSERTION_LIFETIME_SECONDS)
    .sign(request.key);
}
