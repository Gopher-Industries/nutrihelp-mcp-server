# Ticket 49: record_meal

This branch builds on Ticket 48 (`9d3b2d9`) and implements the two-call MCP tool
against Ticket 47's `POST /api/meallog/me` contract. Ticket 48 must be reviewed and
merged first. The backend PR is in a separate repository.

## Implementation and deployment status

The tool, registration, verified request context, confirmation lifecycle, live
grant checks, backend HTTP adapter and tests are implemented here. This is **not
yet an enabled production write flow**: `src/server.ts` deliberately does not
supply `RecordMealServices` until the prerequisite adapters are available. An
authorized caller can discover the tool, but calling it without those adapters
returns a sanitized `upstream_failure` and creates no confirmation or meal.

The composition root must pass these trusted services as the fourth argument to
`registerTools(server, ctx, config, services)`:

| Service              | Required behavior / owner                                                                                                                                                                                                                      |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `confirmations`      | Ticket 48's `connectConfirmationStore` using Ticket 21's configured shared Render Key Value. Reuse one process connection; close it during shutdown. No process-local fallback.                                                                |
| `revocation`         | The same Ticket 59 `RevocationChecker` used by HTTP authentication.                                                                                                                                                                            |
| `exchangeCredential` | Ticket 29/31 exchange and backend authentication integration. Return a backend credential for `meallog:write`, bound to the subject token, with no caller-selected identity. Never return the inbound MCP token. Honor the remaining deadline. |
| `auditStarted`       | Ticket 34's durable audit adapter. Resolve only after ingest or shared buffering succeeds; reject if neither succeeds. Honor the remaining deadline. Never log meal arguments, tokens or credentials.                                          |

The missing adapters are not replaced with successful stubs. The integration tests
substitute audit and exchange explicitly; they do not claim deployment, real token
exchange, audit persistence, or live backend database verification.

## Input decision

The tool accepts Ticket 47's resolved meal snapshot directly. It does not accept
the old illustrative `items` / `consumed_at` fixture, look up recipes, estimate
nutrition, or infer a date. Those transformations need a separate explicit
contract; they cannot silently change what the user confirms.

Required fields are `date` (`YYYY-MM-DD`, real calendar date), `meal_type`
(1–50 characters) and `food_name` (1–200 characters). Optional fields are
`calories`, `protein`, `carbs`, `fat`, `fiber`, `sugar`, `sodium` (nonnegative
numbers or null), and `time` (`HH:MM` / `HH:MM:SS` or null). Omitted nutrition and
time are stored as null by Ticket 47. Zero remains different from null.

Only `confirmation_token` is added as a control field. Extra fields, including
identity fields and caller-supplied idempotency keys, are rejected. Both input and
output schemas are published through the SDK; discovery retains the SDK's private,
zero-TTL cache policy.

## Two calls

First call, without a confirmation:

```json
{ "date": "2026-09-18", "meal_type": "breakfast", "food_name": "Porridge", "calories": 200 }
```

The result is `confirmation_required`, with a server-generated summary, the exact
meal fields, a `confirmation_token`, and `expires_at` in epoch milliseconds.
The assistant must show the preview and ask the user to confirm. This call does
not exchange a backend credential or write a meal.

After user confirmation, repeat **all the same meal fields**, adding only the
returned `confirmation_token`. Omitted fields must stay omitted; adding null is
a different argument set. Fields are bound to the verified user, assistant,
connection and tool. Refreshing an access token within the same connection can
preserve that binding; changing the connection cannot.

Before issuing or consuming a confirmation, the handler rechecks the live grant
and requires `meallog:write` in both the signed token and the live answer. It checks
again after durable audit, including before reading a completed result, and again
after credential exchange immediately before writing. Token expiry and the
remaining HTTP request budget are checked at these boundaries. Neither SDK
metadata nor tool arguments can construct the transport's verified context.

## Writes and retries

- Ticket 48's `idempotencyKeyHash` is forwarded unchanged as `Idempotency-Key`:
  exactly 64 lowercase SHA-256 hexadecimal characters. The raw confirmation is
  excluded from the HTTP body and headers; the digest is not hashed again.
- The fixed destination is `/api/meallog/me` on the configured HTTPS backend
  origin. Only the exchanged credential is attached. Redirects are rejected.
- A 200 or 201 response must contain `success: true` and a valid public meal record.
  Bigint IDs remain strings. Backend-only fields are excluded before caching and
  returning the result; responses over 32 KiB are refused.
- Pending calls return a preview; another live claim returns `in_progress` and
  `retry_after_ms`. A completed confirmation returns the same cached `recorded`
  result, after fresh authorization checks, without another backend call.
- A timeout or lost/malformed response can follow a committed database write.
  Retry **the same token and exact meal** after the lease, so Ticket 47 returns the
  original row. The HTTP adapter performs no automatic write retry. Never issue
  a new confirmation merely to recover an uncertain write.
- Changed arguments, unknown tokens and expired pending confirmations are refused.
  Backend 409 is an input/confirmation conflict; 400 is invalid input; 401 and 403
  retain authentication/scope semantics. Unavailability stays retryable, including
  Ticket 47's current default 503 until its authentication adapter is integrated.

## Reproducible checks

Use Node 24 and run:

```sh
npm ci
npm run typecheck
npm run lint
npm run build
npm test
```

For the real Redis suites, use a disposable local database. With Docker Desktop
running, the following PowerShell commands also work on Windows:

```powershell
docker run --detach --rm --name nutrihelp-ticket49-redis -p 127.0.0.1:16379:6379 redis:7-alpine
$env:MCP_CONFIRMATION_TEST_REDIS_URL = "redis://127.0.0.1:16379"
npm.cmd run test:record-meal:redis
docker stop nutrihelp-ticket49-redis
```

The tests reject non-local Redis URLs and delete only their own confirmation keys.
`npm run test:record-meal` runs the tool, context and HTTP-adapter unit tests without
Redis. `test:record-meal:redis` covers both the existing confirmation-store suite
and the new HTTP tool flow, including two independent server/store instances,
concurrency, revocation and response-loss recovery. The added GitHub Actions job
runs these Redis suites with a disposable Redis service.

The repository also contains earlier red-by-design security suites for unfinished
features. In particular, the old consent fixture starts an empty registry and
uses the old `items` shape. It is not silently skipped or weakened by this change.
The new `test/integration/recordMeal.test.ts` runs the actual registry and current
Ticket 47 snapshot contract.

## Local verification

Verified on Node 24.19.0 against the Ticket 48 base `9d3b2d9`:

| Check                                             | Result                                                          |
| ------------------------------------------------- | --------------------------------------------------------------- |
| Typecheck, ESLint, Prettier, build                | Passed                                                          |
| Unit tests                                        | 771 passed (69 added by this branch)                            |
| Protocol conformance                              | 83 passed                                                       |
| Confirmation store + record_meal with local Redis | 35 passed (22 existing + 13 new)                                |
| Egress, upstream-mock and composition controls    | 147 passed                                                      |
| Full security suite                               | 189 passed, 5 failed; the same five fail on the unmodified base |
| Dependency audit, high-severity gate              | Passed; three existing moderate Vitest advisories remain        |

The five existing failures are the two empty-registry confirmation fixtures,
the unfinished meal-plan registry and response-shaping fixtures, and an upstream
test whose substring assertion matches Node's `user-agent` header. No security
tests were deleted or skipped. GitHub Actions has been added but has not run until
this branch is pushed.
