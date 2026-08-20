import express, { type Express, type Request, type Response } from 'express';
import { createMcpHandler, type McpServerFactory } from '@modelcontextprotocol/server';
import { originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import { errors, type JWTPayload } from 'jose';
import { KeySetUnavailableError, type TokenValidator } from '../auth/tokenValidator.ts';
import {
  insufficientScopeChallenge,
  invalidTokenChallenge,
  safeInOneLine,
  unauthenticatedChallenge,
  protectedResourceMetadataUrl,
} from '../auth/challenge.ts';
import {
  protectedResourceMetadataPaths,
  type ProtectedResourceMetadata,
} from '../auth/metadata.ts';

/**
 * Routing headers, read before dispatch so a scope check does not consume the body.
 * Trusted only to select a scope requirement — and that selection is trust. The handler
 * compares them to the body afterwards, so a value that is not already plain is refused.
 */
export interface RequestRouting {
  readonly method: string | undefined;
  readonly name: string | undefined;
}

/**
 * Scope this request needs and the grant does not carry, or `undefined` if it suffices.
 * Must be one of this server's frozen scope names, never a value from a token or request.
 * Unset while no tool exists: absent resolver means nothing to check, not "check nothing".
 */
export type MissingScopeResolver = (
  routing: RequestRouting,
  claims: JWTPayload
) => string | undefined;

export interface AuthorizationOptions {
  readonly validator: TokenValidator;
  readonly missingScopeFor?: MissingScopeResolver;
}

/**
 * Named opt-out for transport-only tests. A literal so it cannot be produced by forgetting
 * a field; it reads as a decision in the diff.
 */
export interface UnauthenticatedTransport {
  readonly unauthenticated: 'transport-tests-only';
}

/**
 * Narrow on `'validator' in options`, not the sentinel. Excess-property checking against a
 * union admits any property from any member, so an object with both would typecheck; asking
 * for the sentinel would send that object down the open path.
 */
function authorizes(
  options: AuthorizationOptions | UnauthenticatedTransport
): options is AuthorizationOptions {
  return 'validator' in options;
}

export interface TransportOptions {
  /** Fresh server instance per request. The core is stateless. */
  readonly factory: McpServerFactory;
  readonly allowedOriginHostnames: readonly string[];
  /**
   * Required. The opt-out is a value, not an omitted field — omitting would disable auth
   * with nothing to notice it.
   */
  readonly authorization: AuthorizationOptions | UnauthenticatedTransport;
  /** RFC 9728 document. Required; routes and challenge pointer derive from `resource`. */
  readonly resourceMetadata: ProtectedResourceMetadata;
  /** Reporting only; never alters the response. */
  readonly onError?: (error: Error) => void;
}

interface Denial {
  readonly status: number;
  readonly challenge?: string;
}

/** `Bearer <token>`, scheme matched case-insensitively per RFC 6750. */
const BEARER_CREDENTIAL = /^bearer\s+(\S+)\s*$/i;

/**
 * Plain method/tool name. Encoded forms are refused rather than decoded here — the handler
 * would otherwise select a scope from a different string than it later compares.
 * Comma/space excluded because Node joins duplicate headers with `, `.
 * `:` excluded: a URI-shaped capability name would 400; revisit when one is added.
 */
const PLAIN_ROUTING_VALUE = /^[A-Za-z][A-Za-z0-9_\-/]*$/;

/**
 * Operator codes from error class and, for claims, the claim name — never message, payload,
 * or cause (jose hangs the decoded token on both). Map, not object: object lookup answers
 * inherited keys, so a claim named `constructor` would return a function.
 */
const CLAIM_REJECTION_CODES = new Map<string, string>([
  ['iss', 'unauthorized.issuer_mismatch'],
  ['aud', 'unauthorized.audience_mismatch'],
  ['type', 'unauthorized.type_mismatch'],
]);

/** Token-shaped refusals with nothing more specific to say. Matched positively so the fall-through stays empty. */
const CREDENTIAL_SHAPED_FAILURES = [
  errors.JOSEAlgNotAllowed,
  errors.JOSENotSupported,
  errors.JWSInvalid,
  errors.JWTInvalid,
  errors.JWKInvalid,
  errors.JWKSMultipleMatchingKeys,
] as const;

type ValidationFailure =
  | { readonly about: 'credential'; readonly code: string }
  | { readonly about: 'key_set'; readonly code: string };

function credentialFailure(code: string): ValidationFailure {
  return { about: 'credential', code };
}

function classifyValidationFailure(cause: unknown): ValidationFailure {
  // Only route to the key-set arm. Fall-through is credential: a 401 refresh loop is visible;
  // answering "retry later" forever for a token that will never verify is not.
  if (cause instanceof KeySetUnavailableError) {
    return { about: 'key_set', code: `upstream_failure.key_set_${cause.failure}` };
  }
  if (cause instanceof errors.JWTExpired) return credentialFailure('unauthorized.expired');
  if (cause instanceof errors.JWTClaimValidationFailed) {
    return credentialFailure(
      CLAIM_REJECTION_CODES.get(cause.claim) ?? 'unauthorized.claim_rejected'
    );
  }
  if (cause instanceof errors.JWSSignatureVerificationFailed) {
    return credentialFailure('unauthorized.signature_rejected');
  }
  // Unknown kid: the set was reachable and did not contain that key — the token's problem.
  if (cause instanceof errors.JWKSNoMatchingKey) {
    return credentialFailure('unauthorized.unknown_key');
  }
  if (CREDENTIAL_SHAPED_FAILURES.some((shape) => cause instanceof shape)) {
    return credentialFailure('unauthorized.token_rejected');
  }
  return credentialFailure('unauthorized.unclassified');
}

/** Array shape is for `set-cookie`; these three fields are always a string. Honour the type. */
function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value.join(', ') : value;
}

function bearerToken(header: string | undefined): string | undefined {
  return BEARER_CREDENTIAL.exec(header ?? '')?.[1];
}

function isPlainRouting(value: string | undefined): boolean {
  return value === undefined || PLAIN_ROUTING_VALUE.test(value);
}

export function createHttpApp(options: TransportOptions): Express {
  const app = express();
  app.disable('x-powered-by');

  const handler = createMcpHandler(options.factory, {
    // 2026-07-28 only; the default would serve 2025-era traffic.
    legacy: 'reject',
    ...(options.onError === undefined ? {} : { onerror: options.onError }),
  });

  // Adapter answers its own 500 then resolves, so this is the only way those surface.
  const mcpHandler = toNodeHandler(handler, {
    ...(options.onError === undefined ? {} : { onerror: options.onError }),
  });
  const validateOrigin = originValidation([...options.allowedOriginHostnames]);

  function report(code: string): void {
    options.onError?.(new Error(code));
  }

  function dispatch(req: Request, res: Response): void {
    void mcpHandler(req, res).catch((cause: unknown) => {
      options.onError?.(cause instanceof Error ? cause : new Error(String(cause)));
      if (!res.headersSent) {
        res.status(500).end();
      }
    });
  }

  async function denyReason(auth: AuthorizationOptions, req: Request): Promise<Denial | undefined> {
    // Routing first, unconditional: the next reader of these names (audit, scope) must not
    // inherit an unvalidated value just because no resolver is wired yet.
    const routing: RequestRouting = {
      method: headerValue(req.headers['mcp-method']),
      name: headerValue(req.headers['mcp-name']),
    };
    if (!isPlainRouting(routing.method) || !isPlainRouting(routing.name)) {
      report('bad_request.routing_header_not_plain');
      return { status: 400 };
    }

    const authorizationHeader = headerValue(req.headers.authorization);
    const token = bearerToken(authorizationHeader);
    if (token === undefined) {
      // Absent header starts the connect flow (not logged). Present-but-unparseable is.
      if (authorizationHeader !== undefined) {
        report('unauthorized.malformed_credential');
      }
      return { status: 401, challenge: unauthenticatedChallenge(resourceMetadataUrl) };
    }

    let claims: JWTPayload;
    try {
      claims = await auth.validator.validate(token);
    } catch (cause: unknown) {
      // Class and claim name only. jose attaches the decoded payload to the error and its cause.
      const failure = classifyValidationFailure(cause);
      report(failure.code);
      if (failure.about === 'key_set') {
        // 401 would send every client refreshing against the component that is already down.
        return { status: 503 };
      }
      return { status: 401, challenge: invalidTokenChallenge(resourceMetadataUrl) };
    }

    // Live grant introspection belongs here, between validation and scope. Not built yet.

    const missingScope = auth.missingScopeFor?.(routing, claims);
    if (missingScope !== undefined) {
      report(`insufficient_scope.${safeInOneLine(missingScope)}`);
      return {
        status: 403,
        challenge: insufficientScopeChallenge(resourceMetadataUrl, missingScope),
      };
    }

    return undefined;
  }

  async function authorizeThenDispatch(
    auth: AuthorizationOptions,
    req: Request,
    res: Response
  ): Promise<void> {
    const denial = await denyReason(auth, req);
    if (denial !== undefined) {
      res.status(denial.status);
      if (denial.challenge !== undefined) {
        res.set('WWW-Authenticate', denial.challenge);
      }
      res.end();
      return;
    }
    dispatch(req, res);
  }

  // Public, unauthenticated, no Origin guard. Pointer and routes both come from `resource`.
  const metadataPaths = protectedResourceMetadataPaths(options.resourceMetadata.resource);
  const resourceMetadataUrl = protectedResourceMetadataUrl(options.resourceMetadata.resource);
  function serveResourceMetadata(_req: Request, res: Response): void {
    res.json(options.resourceMetadata);
  }
  app.get(metadataPaths.primary, serveResourceMetadata);
  app.get(metadataPaths.rootProbe, serveResourceMetadata);

  app.all('/mcp', (req, res) => {
    if (!validateOrigin(req, res)) {
      return;
    }

    const auth = options.authorization;
    if (!authorizes(auth)) {
      dispatch(req, res);
      return;
    }

    void authorizeThenDispatch(auth, req, res).catch((cause: unknown) => {
      options.onError?.(cause instanceof Error ? cause : new Error(String(cause)));
      if (!res.headersSent) {
        res.status(500).end();
      }
    });
  });

  return app;
}
