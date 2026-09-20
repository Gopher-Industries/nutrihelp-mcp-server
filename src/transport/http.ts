import express, { type Express, type Request, type Response } from 'express';
import {
  createMcpHandler,
  type AuthInfo,
  type McpRequestContext,
  type McpServerFactory,
} from '@modelcontextprotocol/server';
import { originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import { errors, type JWTPayload } from 'jose';
import { randomUUID } from 'node:crypto';
import { KeySetUnavailableError, type TokenValidator } from '../auth/tokenValidator.ts';
import type { ActiveGrant, RevocationChecker } from '../auth/revocation.ts';
import type { UpstreamCredentialProvider } from '../auth/upstreamToken.ts';
import { McpError } from '../errors.ts';
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
 *
 * **Three arguments, because introspection is authoritative over the signed claim.** The grant is
 * what live introspection returned for *this* request; `undefined` means no check established one
 * and the resolver must refuse rather than fall back to the token. *(Widened here by ticket 87 —
 * ticket 86 could not, being forbidden from touching this file, and bridged the gap with a shim
 * that has since been deleted. The shape is ticket 49's, adopted rather than reinvented.)*
 */
export type MissingScopeResolver = (
  routing: RequestRouting,
  claims: JWTPayload,
  grant: ActiveGrant | undefined
) => string | undefined;

/**
 * Everything one request established, held by object identity against the `AuthInfo` the SDK hands
 * every tool handler back as `ctx.authInfo`. **The grant is carried, never rebuilt**: it is branded
 * by `revocation.ts` and bound to a token digest, so a value reaching here is evidence that a live
 * check ran for this exact token — and decomposing it into strings would throw that evidence away.
 */
export interface RequestAuthorization {
  /** What live introspection returned for this request. Branded; never widened or forged. */
  readonly grant: ActiveGrant;
  /**
   * The inbound access token. **Reachable only through this record**, never through `AuthInfo`,
   * so a tool handler cannot forward it upstream as a bearer credential.
   */
  readonly subjectToken: string;
  readonly correlationId: string;
  /**
   * Absolute epoch-ms instant the whole request must finish by — **not** a duration. A duration
   * handed to a later stage is a fresh full budget wearing the right name; an instant cannot be
   * re-spent.
   */
  readonly deadlineAt: number;
  /** The clock `deadlineAt` was measured on. Injected so budget exhaustion is testable. */
  readonly now: () => number;
  /** Step 4, consumed lazily and only by a tool whose backing endpoint is credentialed. */
  readonly credentialFor: UpstreamCredentialProvider['credentialFor'];
}

/**
 * How dispatch reaches what the transport established.
 *
 * **The anti-forgery property is object IDENTITY, not field equality.** A JSON-decoded argument or
 * a `_meta` blob with the same fields is a different object, so it is not a key in the map and the
 * lookup misses. That is the whole mechanism; nothing here inspects the value handed in.
 */
export type AuthorizationLookup = (
  authInfo: AuthInfo | undefined
) => RequestAuthorization | undefined;

/**
 * The factory this module drives. The SDK's own `McpServerFactory` takes the request context
 * alone; the second argument is how the composition root reaches the per-app lookup without
 * importing this module's internals or inverting the import chain.
 */
export type AuthorizedServerFactory = (
  ctx: McpRequestContext,
  authorizationFor: AuthorizationLookup
) => ReturnType<McpServerFactory>;

/**
 * `toNodeHandler` reads the authenticated identity off `req.auth` and passes it to the factory as
 * `ctx.authInfo` **by reference**, which is what makes identity-keyed lookup work. Express's
 * `Request` does not declare the field.
 */
type AuthenticatedRequest = Request & { auth?: AuthInfo };

/**
 * Named opt-out for transport-only tests, mirroring `UnauthenticatedTransport`. Live grant
 * introspection has **no exemption** — not for `tools/list`, not for a public backing endpoint —
 * so the field below is required and this is the only way to be without one. Omitting a field
 * would disable the check with nothing to notice it; a literal reads as a decision in the diff.
 */
export interface RevocationDisabled {
  readonly revocationDisabled: 'transport-tests-only';
}

/**
 * Named opt-out for transport-only tests, for the same reason as the two above: a request that
 * reaches a credentialed tool with no provider must not quietly dispatch without one. The third
 * sentinel, and `test/security/compositionRoot.test.ts` carries a third absence case for it.
 */
export interface CredentialsDisabled {
  readonly credentialsDisabled: 'transport-tests-only';
}

export interface AuthorizationOptions {
  readonly validator: TokenValidator;
  /** Required — omit would silently skip live introspection; use `RevocationDisabled` to opt out. */
  readonly revocation: RevocationChecker | RevocationDisabled;
  /**
   * Step 4's minter, passed in rather than imported: the transport cannot import `src/server.ts`
   * without inverting the import chain. **Required for the same reason `revocation` is** — an
   * omitted field disables the step with nothing to notice it, where a literal reads as a decision
   * in the diff. Nothing is exchanged here; the registry consumes it per tool, and only for a tool
   * whose backing endpoint is credentialed.
   */
  readonly credentials: UpstreamCredentialProvider | CredentialsDisabled;
  /**
   * The **one** end-to-end budget for a request, not a per-call timeout. Offline validation
   * already spends from it — its key-set fetch is an outbound call — so introspection is handed
   * what **remains**, never a fresh copy. Two stages each taking the full value would let a
   * request run to twice the configured deadline.
   */
  readonly requestDeadlineMs: number;
  /** Injected so budget exhaustion is testable without waiting. Defaults to the real clock. */
  readonly now?: () => number;
  readonly missingScopeFor?: MissingScopeResolver;
}

/** Narrow on the checker, not the sentinel — same reasoning as `authorizes` below. */
function checksRevocation(
  revocation: RevocationChecker | RevocationDisabled
): revocation is RevocationChecker {
  return 'assertGrantActive' in revocation;
}

/** Likewise: narrow on the capability, never on the opt-out's own property name. */
function mintsCredentials(
  credentials: UpstreamCredentialProvider | CredentialsDisabled
): credentials is UpstreamCredentialProvider {
  return 'credentialFor' in credentials;
}

/**
 * The provider a request is handed when the composition opted out. It refuses rather than
 * returning nothing, so the opt-out cannot be mistaken for a public backing endpoint: a tool that
 * declares it needs a credential and is handed none must fail, not proceed without one.
 */
const REFUSES_TO_MINT: UpstreamCredentialProvider = {
  credentialFor: () =>
    Promise.reject(
      new Error('the transport was composed on the credential opt-out, so no exchange can run')
    ),
};

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
  /**
   * Fresh server instance per request. The core is stateless. Handed this app's authorization
   * lookup as its second argument, which is how the registry reads what this request established.
   */
  readonly factory: AuthorizedServerFactory;
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

/**
 * What the authorization stages concluded. A granted request carries the record dispatch will
 * read — or `undefined` under the revocation opt-out, where no grant was ever established and so
 * no `AuthInfo` is minted and every tool refuses.
 */
type Decision =
  | { readonly outcome: 'denied'; readonly denial: Denial }
  | { readonly outcome: 'granted'; readonly authorization: RequestAuthorization | undefined };

function denied(denial: Denial): Decision {
  return { outcome: 'denied', denial };
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

  /**
   * **Closure-scoped, not module-scoped.** One app instance must not be able to answer another
   * instance's request: a module-level map would be shared by every `createHttpApp` in a process,
   * which is the shape a test harness makes real long before production does.
   *
   * Weak so an entry dies with the `AuthInfo` the request built, with no eviction policy to get
   * wrong — and keyed by identity, which is what makes it unforgeable from request content.
   */
  const authorizations = new WeakMap<AuthInfo, RequestAuthorization>();

  const authorizationFor: AuthorizationLookup = (authInfo) =>
    authInfo === undefined ? undefined : authorizations.get(authInfo);

  const handler = createMcpHandler(
    (ctx: McpRequestContext) => options.factory(ctx, authorizationFor),
    {
      // 2026-07-28 only; the default would serve 2025-era traffic.
      legacy: 'reject',
      ...(options.onError === undefined ? {} : { onerror: options.onError }),
    }
  );

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

  async function decide(
    auth: AuthorizationOptions,
    req: Request,
    correlationId: string
  ): Promise<Decision> {
    // The clock for this request's single budget. Started before the first stage that can spend
    // from it, so every later stage measures against the same origin.
    const clock = auth.now ?? Date.now;
    const startedAt = clock();

    /**
     * The one budget as an **instant**, computed once. Every later stage subtracts the clock from
     * this, so no stage can be handed a fresh full duration — which is the defect ticket 71 exists
     * for, and which shipped once already past a green gate.
     */
    const deadlineAt = startedAt + auth.requestDeadlineMs;

    // Routing first, unconditional: the next reader of these names (audit, scope) must not
    // inherit an unvalidated value just because no resolver is wired yet.
    const routing: RequestRouting = {
      method: headerValue(req.headers['mcp-method']),
      name: headerValue(req.headers['mcp-name']),
    };
    if (!isPlainRouting(routing.method) || !isPlainRouting(routing.name)) {
      report('bad_request.routing_header_not_plain');
      return denied({ status: 400 });
    }

    const authorizationHeader = headerValue(req.headers.authorization);
    const token = bearerToken(authorizationHeader);
    if (token === undefined) {
      // Absent header starts the connect flow (not logged). Present-but-unparseable is.
      if (authorizationHeader !== undefined) {
        report('unauthorized.malformed_credential');
      }
      return denied({ status: 401, challenge: unauthenticatedChallenge(resourceMetadataUrl) });
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
        return denied({ status: 503 });
      }
      return denied({ status: 401, challenge: invalidTokenChallenge(resourceMetadataUrl) });
    }

    // Between validation and scope; no exemption for tools/list or public backing endpoints.
    let grant: ActiveGrant | undefined;
    if (checksRevocation(auth.revocation)) {
      // What is LEFT of the one budget, not a fresh copy of it. Offline validation above has
      // already spent from it — its key-set fetch goes out through the one door — so handing the
      // full value here would let a single request run to twice the configured deadline.
      const remainingMs = deadlineAt - clock();
      if (remainingMs <= 0) {
        // Exhausted before the check could run. Refuse rather than ask with no budget: an
        // unanswerable introspection is the retryable class, never an authentication failure.
        report('upstream_failure.deadline_exhausted');
        return denied({ status: 503 });
      }
      try {
        // **Captured, not discarded.** The grant is what steps 3 and 4 are entitled to read, and
        // throwing it away here is what forced a connection-keyed shim that failed open.
        grant = await auth.revocation.assertGrantActive({
          token,
          correlationId,
          deadlineMs: remainingMs,
        });
      } catch (cause: unknown) {
        // Only authenticated active:false → 401. Unreachable / 5xx / malformed → retryable 503.
        if (cause instanceof McpError && cause.class === 'unauthorized') {
          return denied({ status: 401, challenge: invalidTokenChallenge(resourceMetadataUrl) });
        }
        return denied({ status: 503 });
      }
    }

    const missingScope = auth.missingScopeFor?.(routing, claims, grant);
    if (missingScope !== undefined) {
      report(`insufficient_scope.${safeInOneLine(missingScope)}`);
      return denied({
        status: 403,
        challenge: insufficientScopeChallenge(resourceMetadataUrl, missingScope),
      });
    }

    if (grant === undefined) {
      // The revocation opt-out. Nothing established a grant, so nothing is bound to the request
      // and every tool refuses at dispatch — the transport-only posture, stated rather than faked.
      return { outcome: 'granted', authorization: undefined };
    }

    const credentials = mintsCredentials(auth.credentials) ? auth.credentials : REFUSES_TO_MINT;
    return {
      outcome: 'granted',
      authorization: {
        grant,
        subjectToken: token,
        correlationId,
        deadlineAt,
        now: clock,
        credentialFor: credentials.credentialFor,
      },
    };
  }

  /**
   * The identity every tool handler can read, as `ctx.authInfo`.
   *
   * **`token` carries the token's DIGEST, not the token, and that DEVIATES from the SDK's
   * documented meaning of this field — it is deliberate, decided by the team lead, and must not be
   * "corrected".** `AuthInfo` reaches every handler, and a handler that forwards `token` upstream
   * as a bearer credential breaks the no-passthrough rule; one branch already does exactly that. A digest
   * makes that forwarding fail loudly at the backend instead of working. The real token stays in
   * `RequestAuthorization`, which only the registry can reach.
   *
   * `clientId` and `scopes` come from the **grant**, never from the JWT claims: introspection is
   * authoritative, and a token minted before a user narrowed a connection still carries the wider
   * claim.
   */
  function authInfoFor(authorization: RequestAuthorization): AuthInfo {
    return {
      token: authorization.grant.tokenDigest,
      clientId: authorization.grant.clientId,
      scopes: [...authorization.grant.scopes],
    };
  }

  async function authorizeThenDispatch(
    auth: AuthorizationOptions,
    req: Request,
    res: Response,
    correlationId: string
  ): Promise<void> {
    const decision = await decide(auth, req, correlationId);
    if (decision.outcome === 'denied') {
      res.status(decision.denial.status);
      if (decision.denial.challenge !== undefined) {
        res.set('WWW-Authenticate', decision.denial.challenge);
      }
      res.end();
      return;
    }

    if (decision.authorization !== undefined) {
      const authInfo = authInfoFor(decision.authorization);
      authorizations.set(authInfo, decision.authorization);
      // The SDK passes this object through by reference, so what the registry looks up is the
      // very object written here — which is what makes identity the anti-forgery property.
      (req as AuthenticatedRequest).auth = authInfo;
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
      // The transport-only opt-out. No stage runs, nothing is reported and nothing goes upstream,
      // so there is nothing to correlate — and minting an identifier above this line would create
      // one per request that no record ever carries. Said here because "minted per request" and
      // "minted and discarded on one path" read identically at the call site.
      dispatch(req, res);
      return;
    }

    // One id for every stage, minted HERE so it precedes every stage that reports and every
    // stage that calls out. It used to be minted where the first stage needing it ran — after
    // routing validation and the credential check — so the earliest refusals carried none.
    const correlationId = randomUUID();

    void authorizeThenDispatch(auth, req, res, correlationId).catch((cause: unknown) => {
      options.onError?.(cause instanceof Error ? cause : new Error(String(cause)));
      if (!res.headersSent) {
        res.status(500).end();
      }
    });
  });

  return app;
}
