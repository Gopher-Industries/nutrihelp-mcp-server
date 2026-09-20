/**
 * The one place a test forges an `ActiveGrant`.
 *
 * `src/auth/revocation.ts` brands that type with a `unique symbol` it does not export, so the
 * only value satisfying it is one that module produced after a live introspection answered
 * `active: true`. That is deliberate, and it is the whole structural half of the ordering rule:
 * a function taking an `ActiveGrant` cannot be reached without the check having run.
 *
 * A test still needs one without paying for a wire round trip, and the escape hatch is an
 * `as unknown as` double cast. **Kept in one named function rather than spread across suites**
 * for two reasons: the cast is then visible in review as a single, greppable exception, and any
 * suite reaching for it has to import something called "forge", which is a harder thing to do by
 * accident than to write an object literal.
 *
 * **`tokenDigest` is computed here with the production function, never typed out.** A forge that
 * hand-wrote a digest would be a second statement of the algorithm, and the drift would be
 * invisible: every grant would simply be refused, and the suites would read as though the
 * binding check were firing correctly when it was firing on the fixture instead.
 *
 * ⚠️ The security proof of that rule must NOT use this. A forged grant proves the type is
 * forgeable, which is already known. `test/security/auth/upstreamToken.test.ts` drives the real
 * revocation checker against the real mocked endpoint and uses what it returns.
 */

import type { ActiveGrant } from '../../src/auth/revocation.ts';
import { subjectTokenDigest } from '../../src/auth/upstreamToken.ts';
import { ALL_SCOPES, CLIENT_ID, GRANT_A, USER_A } from './testEnv.ts';

/** The token a forged grant is bound to unless a suite names its own. */
export const FORGED_SUBJECT_TOKEN = 'forged-subject-token';

export interface ForgedGrantFields {
  readonly grantId?: string;
  readonly scopes?: readonly string[];
  readonly subject?: string;
  readonly clientId?: string;
  /** The token this grant claims to have been checked against. */
  readonly subjectToken?: string;
}

/** A grant shaped like a live one, with none of the evidence behind it. Tests only. */
export function forgeActiveGrant(fields: ForgedGrantFields = {}): ActiveGrant {
  return {
    grantId: fields.grantId ?? GRANT_A,
    scopes: fields.scopes ?? ALL_SCOPES,
    subject: fields.subject ?? USER_A,
    clientId: fields.clientId ?? CLIENT_ID,
    tokenDigest: subjectTokenDigest(fields.subjectToken ?? FORGED_SUBJECT_TOKEN),
  } as unknown as ActiveGrant;
}
