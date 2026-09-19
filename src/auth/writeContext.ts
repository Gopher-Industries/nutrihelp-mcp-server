import type { AuthInfo } from '@modelcontextprotocol/server';
import type { JWTPayload } from 'jose';
import type { ActiveGrant, RevocationChecker } from './revocation.ts';
import { McpError } from '../errors.ts';

export const MEAL_LOG_WRITE_SCOPE = 'meallog:write';

/** Routing headers are validated and subsequently matched to the body by the HTTP adapter. */
export function missingRecordMealScope(
  routing: { readonly method: string | undefined; readonly name: string | undefined },
  claims: JWTPayload,
  live: ActiveGrant | undefined
): string | undefined {
  if (routing.method !== 'tools/call' || routing.name !== 'record_meal') return undefined;
  const signedScopes = typeof claims.scope === 'string' ? claims.scope.split(/\s+/) : [];
  return signedScopes.includes(MEAL_LOG_WRITE_SCOPE) && live?.scopes.includes(MEAL_LOG_WRITE_SCOPE)
    ? undefined
    : MEAL_LOG_WRITE_SCOPE;
}

export interface WriteContext {
  readonly token: string;
  readonly userId: string;
  readonly assistantId: string;
  readonly connectionId: string;
  readonly tokenScopes: readonly string[];
  readonly liveScopes: readonly string[];
  readonly expiresAt: number;
  readonly correlationId: string;
  readonly deadlineAt: number;
  readonly now: () => number;
  readonly resourceMetadataUrl: string;
}

// Only transport-created auth objects unlock write tools. Tool arguments and _meta cannot
// manufacture this binding, even if they contain identically named properties.
const verifiedContexts = new WeakMap<AuthInfo, WriteContext>();

export function createWriteAuthInfo(
  claims: JWTPayload,
  grant: ActiveGrant,
  request: Pick<
    WriteContext,
    'token' | 'correlationId' | 'deadlineAt' | 'now' | 'resourceMetadataUrl'
  >
): AuthInfo | undefined {
  if (
    claims.sub !== grant.subject ||
    claims.client_id !== grant.clientId ||
    claims.grant_id !== grant.grantId ||
    typeof claims.exp !== 'number'
  )
    return undefined;
  const tokenScopes =
    typeof claims.scope === 'string' ? claims.scope.split(/\s+/).filter(Boolean) : [];
  const auth: AuthInfo = {
    token: request.token,
    clientId: grant.clientId,
    scopes: tokenScopes.filter((scope) => grant.scopes.includes(scope)),
    expiresAt: claims.exp,
  };
  verifiedContexts.set(
    auth,
    Object.freeze({
      ...request,
      userId: grant.subject,
      assistantId: grant.clientId,
      connectionId: grant.grantId,
      tokenScopes: Object.freeze([...tokenScopes]),
      liveScopes: Object.freeze([...grant.scopes]),
      expiresAt: claims.exp,
    })
  );
  return auth;
}

export function writeContextFor(auth: AuthInfo | undefined): WriteContext | undefined {
  return auth === undefined ? undefined : verifiedContexts.get(auth);
}

export function writeUnavailable(context: WriteContext, code: string): McpError {
  return new McpError({
    class: 'upstream_failure',
    statusClass: 'unavailable',
    errorCode: code,
    endpointClass: 'meal_log',
    correlationId: context.correlationId,
    latencyMs: 0,
  });
}

export function remainingWriteBudget(context: WriteContext): number {
  const remaining = context.deadlineAt - context.now();
  if (remaining <= 0) throw writeUnavailable(context, 'deadline_exhausted');
  return remaining;
}

function refuseIdentity(context: WriteContext): never {
  throw new McpError({
    class: 'unauthorized',
    reason: 'write_identity_rejected',
    resourceMetadataUrl: context.resourceMetadataUrl,
  });
}

/** Ticket 59 is consulted again on confirmation AND cached-result reads, not just proposal. */
export async function assertMealWriteAuthorized(
  context: WriteContext,
  checker: RevocationChecker
): Promise<void> {
  if (context.expiresAt * 1000 <= context.now()) refuseIdentity(context);
  const live = await checker.assertGrantActive({
    token: context.token,
    correlationId: context.correlationId,
    deadlineMs: remainingWriteBudget(context),
  });
  if (
    live.subject !== context.userId ||
    live.clientId !== context.assistantId ||
    live.grantId !== context.connectionId
  )
    refuseIdentity(context);
  if (context.expiresAt * 1000 <= context.now()) refuseIdentity(context);
  if (
    !context.tokenScopes.includes(MEAL_LOG_WRITE_SCOPE) ||
    !live.scopes.includes(MEAL_LOG_WRITE_SCOPE)
  ) {
    throw new McpError({
      class: 'insufficient_scope',
      requiredScope: MEAL_LOG_WRITE_SCOPE,
      heldScopes: live.scopes,
      resourceMetadataUrl: context.resourceMetadataUrl,
      userId: context.userId,
      clientId: context.assistantId,
      grantId: context.connectionId,
      operation: 'record_meal',
    });
  }
  remainingWriteBudget(context);
}
