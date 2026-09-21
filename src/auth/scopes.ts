/**
 * Step 3 of the mandatory order: the frozen scope definitions and the tool-to-scope map.
 *
 * The only statement of the tool-to-scope relation in the tree; the test fixture re-exports these
 * constants and the exact-count pin is `test/unit/auth/scopes.test.ts`, in the unit layer because
 * `validate` chains `npm test` and not `test:security`.
 *
 * **A scope counts only when it is in the signed `scope` claim AND in the grant live introspection
 * just returned.** That is why step 2 precedes step 3: a token minted before a user narrowed a
 * connection stays signed and unexpired, and only the grant says otherwise.
 */

import type { JWTPayload } from 'jose';
import type { ActiveGrant } from './revocation.ts';

/** **The one hand-written statement of the scope set.** Everything else derives from it. */
export const SCOPES = Object.freeze({
  nutritionRead: 'nutrition:read',
  mealplanRead: 'mealplan:read',
  meallogWrite: 'meallog:write',
} as const);

export type ScopeName = (typeof SCOPES)[keyof typeof SCOPES];

/** Derived. `recipe:read` is withdrawn with `find_recipe` and re-enters only with the tool. */
export const SCOPE_NAMES: readonly ScopeName[] = Object.freeze(Object.values(SCOPES));

/**
 * Derived alias for the one scope ticket 49's `writeContext.ts` declares as a literal; its rebase
 * re-exports this instead. **Unannotated on purpose** — an explicit `: ScopeName` would widen it to
 * the union, where the declaration it replaces is the narrow literal.
 */
export const MEAL_LOG_WRITE_SCOPE = SCOPES.meallogWrite;

/** **The one hand-written statement of the tool-to-scope relation.** Values derive from `SCOPES`. */
export const TOOL_SCOPES = Object.freeze({
  nutrition_lookup: SCOPES.nutritionRead,
  get_meal_plan: SCOPES.mealplanRead,
  record_meal: SCOPES.meallogWrite,
} as const);

export type ScopedToolName = keyof typeof TOOL_SCOPES;

/**
 * The explicit opt-out, and the reason it is a word rather than `undefined`.
 *
 * A registered tool absent from the map above used to mean "no scope requirement", because that is
 * what a map miss answers. At the transport that reading is right — the name arrives in a request
 * header and may be a typo. At the registry it is the wrong default: the name comes off a
 * descriptor that IS registered and IS dispatchable, so a miss means nobody assigned the tool a
 * scope, and the safe answer is refuse. A descriptor therefore carries a `ScopeDecision` and
 * `NO_SCOPE` is how one SAYS it needs none, which an omission cannot say.
 *
 * It can never collide with a scope name: every scope above is `resource:action` and carries a
 * colon. Pinned in `test/unit/auth/scopes.test.ts` rather than left to the reader.
 */
export const NO_SCOPE = 'none';

/** What a tool descriptor declares: a scope from the frozen map, or the opt-out above. */
export type ScopeDecision = ScopeName | typeof NO_SCOPE;

/**
 * A `Map`, not the object: a capability name arrives in a request header, and object lookup answers
 * inherited keys — `constructor` would resolve to a function, `__proto__` to the prototype.
 */
const TOOL_SCOPE_BY_NAME: ReadonlyMap<string, ScopeName> = new Map<string, ScopeName>(
  Object.entries(TOOL_SCOPES)
);

/** The only method that carries a per-capability scope requirement today. */
const TOOL_CALL_METHOD = 'tools/call';

/**
 * The routing pair, structurally. A second declaration of the transport's `RequestRouting`, and it
 * **stays** one: `src/auth/**` must not import the transport, and the assignability that makes this
 * work is checked where the composition root hands `missingScopeFor` to `createHttpApp`. The
 * hazard is that it goes **silent** — a field added to `RequestRouting` leaves it assignable to
 * this, so nothing fails and the scope step simply cannot see the new field.
 */
export interface ScopeRouting {
  readonly method: string | undefined;
  readonly name: string | undefined;
}

/**
 * What the one hand-written relation says about this tool NAME, or `undefined` when it names no
 * scope for it. The registry asks this at registration to check a descriptor's declaration against
 * the map; the routing question below is a wrapper on it, so there is one lookup and not two.
 *
 * **A miss is not an answer to "does this tool need a scope".** It says only that the map is
 * silent, and the two callers are entitled to read that silence differently — which is the whole
 * distinction this pair exists to keep.
 */
export function mappedScopeFor(name: string): ScopeName | undefined {
  return TOOL_SCOPE_BY_NAME.get(name);
}

/**
 * What this routing pair requires, or `undefined` when nothing does.
 *
 * **An unknown method and an unknown tool name both yield NO requirement, not a default.** This
 * step answers "which scope does this need", not "does this exist": `tools/list` carries no
 * per-capability requirement here, filtering the listing is the registry's job and is not built yet
 * (ticket 25), and an unregistered name is the dispatcher's 404 — answering 403 would name a scope
 * that grants nothing.
 *
 * **That default is honest HERE and was a fail-open at the registry, which is why the registry no
 * longer calls this.** The name this function is handed arrives in the `Mcp-Name` routing header
 * and the caller chooses it; the name the registry was handing it came off a descriptor that is
 * registered and dispatchable. Same lookup, opposite meaning for a miss. The registry reads the
 * descriptor's `ScopeDecision` instead and refuses to register one that has not made a decision.
 */
export function requiredScopeFor(routing: ScopeRouting): ScopeName | undefined {
  if (routing.method !== TOOL_CALL_METHOD || routing.name === undefined) return undefined;
  return mappedScopeFor(routing.name);
}

/**
 * **The one statement of the scope-split rule.** RFC 6749 `scope` is space-delimited and only
 * space-delimited: split on anything wider and a malformed `"a\tb"` becomes two granted scopes, and
 * the tolerant direction only ever grants. Absent or non-string means no scopes, never "all".
 *
 * `revocation.ts` reads the introspection response through this rather than the byte-identical copy
 * it carried. That rule had already diverged — ticket 49's branch splits on `/\s+/` in two places.
 */
export function parseScopeList(scope: unknown): readonly string[] {
  return typeof scope === 'string' ? scope.split(' ').filter((entry) => entry !== '') : [];
}

/** The `scope` claim of a verified token, through the one rule above. */
export function signedScopes(claims: JWTPayload): readonly string[] {
  return parseScopeList(claims.scope);
}

/**
 * Whether this grant is the one this token names.
 *
 * **All three are compared, not `grant_id` alone**, which would rest the whole pairing on a single
 * token claim nothing in the tree verifies. `revocation.ts` mints `subject`, `clientId` and
 * `grantId` precisely so a consumer can refuse a mismatch — the brand says a check *ran*, not which
 * token it ran for. An absent claim compares unequal, so a token missing any of them refuses.
 */
function bindsToClaims(claims: JWTPayload, grant: ActiveGrant | undefined): grant is ActiveGrant {
  return (
    grant !== undefined &&
    grant.subject === claims.sub &&
    grant.clientId === claims.client_id &&
    grant.grantId === claims.grant_id
  );
}

/**
 * The scope this request needs and does not have, or `undefined` when it may proceed.
 *
 * `grant` is what live introspection returned for this request. **`undefined` refuses**, and so does
 * a grant whose identity disagrees with the token's: a check that could not be run must not be
 * assumed.
 */
export function missingScopeFor(
  routing: ScopeRouting,
  claims: JWTPayload,
  grant: ActiveGrant | undefined
): ScopeName | undefined {
  const required = requiredScopeFor(routing);
  if (required === undefined) return undefined;
  if (!signedScopes(claims).includes(required)) return required;
  if (!bindsToClaims(claims, grant)) return required;
  if (!grant.scopes.includes(required)) return required;
  return undefined;
}
