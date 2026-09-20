/**
 * The frozen scope set, the tool-to-scope map, and the two-sided scope decision. Ticket 86.
 *
 * **This file is the pin, and it lives in the unit layer on purpose.** `validate` chains
 * `npm test`; it does not chain `test:security`. A content pin in the security layer never runs on
 * a pre-push, which is exactly how the identity deny-list came to be deletable byte-identically
 * across every gate. The expected contents below are **hand-written and not derived** — a pin
 * spread from the constant it pins tracks it instead of pinning it, and four entries could then be
 * deleted with identical output. The exact-count assertions are what close the other direction: an
 * entry added without touching this file goes red too.
 */

import { describe, expect, it } from 'vitest';
import type { JWTPayload } from 'jose';
import type { McpRequestContext, McpServer } from '@modelcontextprotocol/server';
import { AUDIT_ENQUEUE_NOT_IMPLEMENTED, registerTools } from '../../../src/tools/registry.ts';
import {
  MEAL_LOG_WRITE_SCOPE,
  NO_SCOPE,
  SCOPES,
  SCOPE_NAMES,
  TOOL_SCOPES,
  mappedScopeFor,
  missingScopeFor,
  requiredScopeFor,
  signedScopes,
  type ScopeRouting,
} from '../../../src/auth/scopes.ts';
import type { ActiveGrant } from '../../../src/auth/revocation.ts';
import { forgeActiveGrant } from '../../support/activeGrant.ts';
import {
  GRANT_A,
  USER_A,
  USER_B,
  CLIENT_ID,
  RESOURCE_METADATA_URL,
} from '../../support/testEnv.ts';

/** Hand-written. The one statement this file is allowed to duplicate, because pinning is its job. */
const EXPECTED_SCOPES = {
  nutritionRead: 'nutrition:read',
  mealplanRead: 'mealplan:read',
  meallogWrite: 'meallog:write',
};

/** Likewise hand-written: the relation, not a projection of the constant it guards. */
const EXPECTED_TOOL_SCOPES = {
  nutrition_lookup: 'nutrition:read',
  get_meal_plan: 'mealplan:read',
  record_meal: 'meallog:write',
};

/** The identity a forged grant carries by default, so claims and grant bind unless a case parts them. */
function claims(fields: Record<string, unknown> = {}): JWTPayload {
  return { sub: USER_A, client_id: CLIENT_ID, grant_id: GRANT_A, ...fields };
}

function grantWith(scopes: readonly string[]): ActiveGrant {
  return forgeActiveGrant({ scopes });
}

function call(name: string | undefined): ScopeRouting {
  return { method: 'tools/call', name };
}

describe('the frozen scope set', () => {
  it('is exactly these three scopes, by name and by count', () => {
    expect(
      SCOPES,
      'the scope set is a consent contract: a name added here is a permission a user is asked to grant, and one removed is a permission already-minted tokens still carry'
    ).toEqual(EXPECTED_SCOPES);
    expect(
      Object.keys(SCOPES),
      'exact count, so an entry added without pinning it here goes red rather than riding in unnoticed — the silent direction is always the enforcing copy gaining an entry the readable copy never mentions'
    ).toHaveLength(3);
  });

  it('withdraws recipe:read with find_recipe, rather than carrying it unused', () => {
    expect(
      Object.values(SCOPES),
      'recipe:read re-enters only with the tool. A scope declared before its tool is a scope a client can request and hold for nothing'
    ).not.toContain('recipe:read');
  });

  it('derives the name list rather than restating it', () => {
    expect(SCOPE_NAMES).toEqual(Object.values(SCOPES));
    expect(SCOPE_NAMES).toHaveLength(Object.keys(SCOPES).length);
  });

  it('derives the write-scope alias, so ticket 49 can re-export it instead of declaring it', () => {
    expect(
      MEAL_LOG_WRITE_SCOPE,
      'the reconciliation point: writeContext.ts declares this as a literal today, and two literals of one scope name is the drift this project has recorded four times'
    ).toBe(SCOPES.meallogWrite);
  });

  it('is frozen at runtime, not only readonly at the type level', () => {
    expect(Object.isFrozen(SCOPES)).toBe(true);
    expect(Object.isFrozen(TOOL_SCOPES)).toBe(true);
    expect(Object.isFrozen(SCOPE_NAMES)).toBe(true);
  });
});

describe('the tool-to-scope map', () => {
  it('is exactly these three tools, by name and by count', () => {
    expect(TOOL_SCOPES).toEqual(EXPECTED_TOOL_SCOPES);
    expect(
      Object.keys(TOOL_SCOPES),
      'exact count: a tool registered without an entry here dispatches with no scope requirement at all'
    ).toHaveLength(3);
  });

  it('spends every declared scope on a tool, so none is grantable for nothing', () => {
    expect(
      [...new Set(Object.values(TOOL_SCOPES))].sort(),
      'a scope no tool needs is consent wording a user reads and a capability nobody can reach'
    ).toEqual([...SCOPE_NAMES].sort());
  });

  it('does not name find_recipe, which does not re-enter v1', () => {
    expect(Object.keys(TOOL_SCOPES)).not.toContain('find_recipe');
  });
});

/**
 * The opt-out a descriptor declares, and the reason it is a word rather than `undefined`.
 *
 * A registry that read "absent from the map" as "needs no scope" dispatched a registered tool
 * nobody had scoped, with no scope check at all. The miss and the deliberate opt-out were the same
 * value, so nothing could tell them apart. These are the assertions that keep them apart.
 */
describe('the explicit no-scope declaration', () => {
  it('is the word none, hand-written here as the pin', () => {
    expect(NO_SCOPE).toBe('none');
  });

  it('can never collide with a scope name, because every scope carries a colon', () => {
    expect(
      SCOPE_NAMES,
      'if a scope were ever named none, a descriptor declaring the opt-out would read as requiring it'
    ).not.toContain(NO_SCOPE);
    expect(
      SCOPE_NAMES.every((name) => name.includes(':')),
      'the property the line above rests on, asserted rather than assumed: resource:action is what makes the two sets disjoint by construction'
    ).toBe(true);
    expect(NO_SCOPE).not.toContain(':');
  });

  it('is not a value the frozen map can produce', () => {
    expect(
      Object.values(TOOL_SCOPES),
      'the map states requirements. The opt-out is a descriptor declaring it has none, which is a different statement and lives in a different place'
    ).not.toContain(NO_SCOPE);
  });
});

/**
 * The lookup by name, which the registry asks at registration and the routing question below wraps.
 * One lookup, two readings of a miss — and the whole defect was that only one reading existed.
 */
describe('the lookup by tool name', () => {
  it.each([
    { name: 'nutrition_lookup', scope: SCOPES.nutritionRead },
    { name: 'get_meal_plan', scope: SCOPES.mealplanRead },
    { name: 'record_meal', scope: SCOPES.meallogWrite },
  ])('answers $scope for $name', ({ name, scope }) => {
    expect(mappedScopeFor(name)).toBe(scope);
  });

  it('answers nothing for a name the map does not carry', () => {
    expect(
      mappedScopeFor('drop_all_meals'),
      'silence, which the transport reads as no requirement and the registry reads as refuse to register'
    ).toBeUndefined();
  });

  it.each(['constructor', '__proto__', 'toString'])(
    'answers nothing for the inherited key %s',
    (name) => {
      expect(mappedScopeFor(name)).toBeUndefined();
    }
  );

  it('is the lookup the routing question uses, rather than a second one beside it', () => {
    for (const name of [...Object.keys(TOOL_SCOPES), 'drop_all_meals', '__proto__']) {
      expect(
        requiredScopeFor(call(name)),
        `${name}: two lookups over one map is the drift this file exists to prevent`
      ).toBe(mappedScopeFor(name));
    }
  });
});

describe('selecting the requirement', () => {
  it.each([
    { label: 'nutrition_lookup', name: 'nutrition_lookup', scope: SCOPES.nutritionRead },
    { label: 'get_meal_plan', name: 'get_meal_plan', scope: SCOPES.mealplanRead },
    { label: 'record_meal', name: 'record_meal', scope: SCOPES.meallogWrite },
  ])('requires $scope for $label', ({ name, scope }) => {
    expect(requiredScopeFor(call(name))).toBe(scope);
  });

  it('requires nothing of tools/list, which is filtered rather than refused', () => {
    expect(
      requiredScopeFor({ method: 'tools/list', name: undefined }),
      'a tool the grant does not cover is omitted from the listing; refusing the whole listing would deny a caller the tools it does hold'
    ).toBeUndefined();
  });

  it.each([
    { label: 'an unknown method', routing: { method: 'resources/read', name: undefined } },
    { label: 'no method at all', routing: { method: undefined, name: undefined } },
    { label: 'a tools/call with no name', routing: call(undefined) },
    { label: 'a tool nobody registered', routing: call('drop_all_meals') },
  ])('yields no requirement for $label, rather than a default', ({ routing }) => {
    expect(
      requiredScopeFor(routing),
      'this step answers which scope an operation needs, not whether it exists. A default requirement here answers 403 to a typo and names a scope that grants nothing'
    ).toBeUndefined();
  });

  /**
   * The name arrives in a request header. Object lookup would answer these from the prototype —
   * `constructor` as a function, `__proto__` as an object — and either one is a non-undefined
   * value flowing into a scope comparison.
   */
  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf'])(
    'answers nothing for the inherited key %s',
    (name) => {
      expect(requiredScopeFor(call(name))).toBeUndefined();
    }
  );
});

describe('reading the signed scope claim', () => {
  it('splits on single spaces per RFC 6749', () => {
    expect(signedScopes(claims({ scope: 'nutrition:read mealplan:read' }))).toEqual([
      'nutrition:read',
      'mealplan:read',
    ]);
  });

  it('tolerates repeated spaces without inventing an empty scope', () => {
    expect(signedScopes(claims({ scope: '  nutrition:read   mealplan:read ' }))).toEqual([
      'nutrition:read',
      'mealplan:read',
    ]);
  });

  it('does not split on a tab, because a tolerant split only ever grants', () => {
    expect(
      signedScopes(claims({ scope: 'nutrition:read\tmeallog:write' })),
      'a malformed claim must not become two granted scopes'
    ).toEqual(['nutrition:read\tmeallog:write']);
  });

  it.each([
    { label: 'absent', value: undefined },
    { label: 'an array', value: ['nutrition:read'] },
    { label: 'an object', value: { nutritionRead: true } },
    { label: 'a number', value: 7 },
    { label: 'null', value: null },
  ])('reads $label as no scopes, never as all of them', ({ value }) => {
    expect(signedScopes(claims({ scope: value }))).toEqual([]);
  });
});

describe('the two-sided decision', () => {
  const granted = claims({ scope: 'nutrition:read meallog:write' });

  it('permits a call whose scope is in the token AND in the live grant', () => {
    expect(
      missingScopeFor(call('record_meal'), granted, grantWith(['meallog:write'])),
      'the granting direction. Without it every assertion here is satisfied by a resolver that refuses everything'
    ).toBeUndefined();
  });

  it('refuses when the token does not carry the scope', () => {
    expect(
      missingScopeFor(call('get_meal_plan'), granted, grantWith(['mealplan:read'])),
      'the grant covers it and the signed claim does not: a scope the user granted to some other client is not one this token may spend'
    ).toBe(SCOPES.mealplanRead);
  });

  /** The half that step 2 exists for. */
  it('refuses a token scope the live grant no longer carries', () => {
    expect(
      missingScopeFor(call('record_meal'), granted, grantWith(['nutrition:read'])),
      'the token is signed, unexpired and says meallog:write. The user narrowed the connection, and the grant is what says so'
    ).toBe(SCOPES.meallogWrite);
  });

  it('refuses when the live grant was never established', () => {
    expect(
      missingScopeFor(call('record_meal'), granted, undefined),
      'a check that could not be run is not a check that passed'
    ).toBe(SCOPES.meallogWrite);
  });

  it('refuses when the live grant carries nothing at all', () => {
    expect(missingScopeFor(call('record_meal'), granted, grantWith([]))).toBe(SCOPES.meallogWrite);
  });

  /**
   * `revocation.ts` mints the grant with `subject`, `clientId` and `grantId` so a consumer can
   * refuse a mismatch. Binding on `grant_id` alone would rest the whole pairing on one token claim
   * that nothing in the tree verifies.
   */
  it.each([
    { label: 'a different subject', grant: forgeActiveGrant({ subject: USER_B }) },
    { label: 'a different client', grant: forgeActiveGrant({ clientId: 'https://other.test/c' }) },
    { label: 'a different connection', grant: forgeActiveGrant({ grantId: 'grant-b-2222' }) },
  ])('refuses a grant that is not the one this token names — $label', ({ grant }) => {
    expect(
      missingScopeFor(call('record_meal'), claims({ scope: 'meallog:write' }), grant),
      'the grant carries every scope asked for; it simply belongs to someone else'
    ).toBe(SCOPES.meallogWrite);
  });

  it.each([
    { label: 'sub', field: 'sub' },
    { label: 'client_id', field: 'client_id' },
    { label: 'grant_id', field: 'grant_id' },
  ])('refuses a token with no $label claim, which binds to nothing', ({ field }) => {
    expect(
      missingScopeFor(
        call('record_meal'),
        claims({ scope: 'meallog:write', [field]: undefined }),
        grantWith(['meallog:write'])
      ),
      'none of these three is a required claim on the verifier, so absence has to fail closed here'
    ).toBe(SCOPES.meallogWrite);
  });

  it('permits a request that needs no scope even with an empty grant', () => {
    expect(
      missingScopeFor({ method: 'tools/list', name: undefined }, claims(), grantWith([])),
      'tools/list carries no requirement, so a caller holding nothing is not refused at this step'
    ).toBeUndefined();
  });
});

/**
 * The map is only a control over what the registry actually registers.
 *
 * **This used to be the ONLY thing holding that property, and it is not any more.** A tool
 * registered with no entry here reached its handler with no scope requirement at all, and this
 * scan was the one artifact that said so — a test, which a branch can be green without ever
 * running. The registry now refuses to register a shipped descriptor the map does not name, at
 * module load, so the property is structural and this stays as the readable statement of it.
 */
describe('every registered tool is in the map', () => {
  it('names a scope for each tool the registry registers', () => {
    const registered: string[] = [];
    const server = {
      registerTool: (name: string): void => {
        registered.push(name);
      },
    } as unknown as McpServer;

    registerTools(server, {} as McpRequestContext, {
      nutrihelpApiBaseUrl: 'https://api.nutrihelp.test',
      // Nothing is dispatched here — only the registered NAMES are read — so a lookup that
      // resolves nothing is the honest fixture.
      authorizationFor: () => undefined,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
      auditEnqueue: AUDIT_ENQUEUE_NOT_IMPLEMENTED,
      // Likewise: nothing is refused here, so there is nothing to report on either channel.
      logSecurity: () => undefined,
      logOperational: () => undefined,
    });

    expect(
      registered.length,
      'control: the registry registered nothing and this scan read air'
    ).toBeGreaterThan(0);
    for (const name of registered) {
      expect(
        requiredScopeFor(call(name)),
        `${name} is dispatchable and the map gives it no scope requirement`
      ).toBeDefined();
    }
  });
});
