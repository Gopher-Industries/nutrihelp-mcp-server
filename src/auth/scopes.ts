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
import type { ActiveGrant, IntrospectionRequest, RevocationChecker } from './revocation.ts';

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
 * A `Map`, not the object: a capability name arrives in a request header, and object lookup answers
 * inherited keys — `constructor` would resolve to a function, `__proto__` to the prototype.
 */
const TOOL_SCOPE_BY_NAME: ReadonlyMap<string, ScopeName> = new Map<string, ScopeName>(
  Object.entries(TOOL_SCOPES)
);

/** The only method that carries a per-capability scope requirement today. */
const TOOL_CALL_METHOD = 'tools/call';

/**
 * The routing pair, structurally. A second declaration of the transport's `RequestRouting`:
 * importing it would **not** be a cycle, so this is deliberate until ticket 87, which owns the
 * transport. ⚠️ The hazard is that it goes **silent** — a field added to `RequestRouting` leaves it
 * assignable to this, so nothing fails and the scope step simply cannot see the new field.
 */
export interface ScopeRouting {
  readonly method: string | undefined;
  readonly name: string | undefined;
}

/**
 * What this routing pair requires, or `undefined` when nothing does.
 *
 * **An unknown method and an unknown tool name both yield NO requirement, not a default.** This
 * step answers "which scope does this need", not "does this exist": `tools/list` is filtered at the
 * registry rather than refused, and an unregistered name is the dispatcher's 404 — answering 403
 * would name a scope that grants nothing.
 */
export function requiredScopeFor(routing: ScopeRouting): ScopeName | undefined {
  if (routing.method !== TOOL_CALL_METHOD || routing.name === undefined) return undefined;
  return TOOL_SCOPE_BY_NAME.get(routing.name);
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

/**
 * The transport's two hooks, wired to each other.
 *
 * ⚠️ **`revocation` must be the checker handed to `createHttpApp`** — the transport discards what
 * `assertGrantActive` returns, so the grant reaches the scope step by being recorded on its way past.
 * **Ticket 87 carries the `ActiveGrant` into dispatch**, passes it as `missingScopeFor`'s third
 * argument, and deletes this hand-off.
 */
export interface ScopeGate {
  readonly revocation: RevocationChecker;
  readonly missingScopeFor: (routing: ScopeRouting, claims: JWTPayload) => ScopeName | undefined;
}

export interface ScopeGateOptions {
  /** Injected so expiry is testable without waiting. */
  readonly now: () => number;
  /**
   * How long a recorded grant may wait to be taken, in ms. **Pass the one request budget**, and no
   * default: this is the only thing bounding the hand-off.
   */
  readonly maxAgeMs: number;
}

/** A grant recorded on its way past, and when. Time-ordered, because `now` only moves forward. */
interface EstablishedGrant {
  readonly grant: ActiveGrant;
  readonly at: number;
}

/**
 * Wrap a revocation checker so the scope step can read the grant that checker just established.
 * Every entry came from an `active: true` answer moments earlier and is taken at most once; a
 * request with no matching entry is refused.
 *
 * ⛔ **It is NOT keyed to the request that wrote it, only to the connection identity, and the
 * failure direction is OPEN.** Two requests overlapping on one connection can take each other's
 * answer: if the grant narrows between their introspections, the later request takes the earlier,
 * wider answer and is permitted a scope the user has just revoked. The fix is a per-request key,
 * which is ticket 87 — not a second binding here.
 *
 * **Bounded by age, not by count.** An entry can be written and never taken (a token whose identity
 * claims disagree with the introspected grant), and a caller can repeat that on ONE connection, so a
 * ceiling counting connections never fires. An entry older than one request budget is one no request
 * is still waiting for, so evicting it costs nothing — where a count ceiling would evict a record an
 * in-flight request was about to want and answer 403 to a scope the user has granted.
 */
export function createScopeGate(checker: RevocationChecker, options: ScopeGateOptions): ScopeGate {
  /** Oldest first, because `record` appends and `now` does not go backwards. */
  const established: EstablishedGrant[] = [];

  function record(grant: ActiveGrant): void {
    const at = options.now();
    established.push({ grant, at });

    const oldestKept = at - options.maxAgeMs;
    let expired = 0;
    for (const entry of established) {
      if (entry.at >= oldestKept) break;
      expired += 1;
    }
    // `splice(0, 0)` is a no-op, so no guard: a guard here is a branch that adds nothing.
    established.splice(0, expired);
  }

  function take(claims: JWTPayload): ActiveGrant | undefined {
    const entry = established.find((candidate) => bindsToClaims(claims, candidate.grant));
    if (entry === undefined) return undefined;
    established.splice(established.indexOf(entry), 1);
    return entry.grant;
  }

  return {
    revocation: {
      assertGrantActive: async (request: IntrospectionRequest): Promise<ActiveGrant> => {
        const grant = await checker.assertGrantActive(request);
        record(grant);
        return grant;
      },
    },
    missingScopeFor: (routing: ScopeRouting, claims: JWTPayload): ScopeName | undefined =>
      missingScopeFor(routing, claims, take(claims)),
  };
}
