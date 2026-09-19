# Ticket 49: record_meal

This branch builds on Ticket 48 (`4b1d1f5`) and implements the two-call MCP tool
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

| Service              | Required behavior / owner                                                                                                                                                                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `confirmations`      | Ticket 48's `connectConfirmationStore` using Ticket 21's configured shared Render Key Value. Set `leaseMs` strictly above the maximum HTTP request deadline (the tests use a 60 s lease for a 30 s request budget). Reuse one process connection; close it during shutdown. No process-local fallback. |
| `revocation`         | The same Ticket 59 `RevocationChecker` used by HTTP authentication.                                                                                                                                                                                                                                    |
| `exchangeCredential` | Ticket 29/31 exchange and backend authentication integration. Return a backend credential for `meallog:write`, bound to the subject token, with no caller-selected identity. Never return the inbound MCP token. Honor the remaining deadline.                                                         |
| `auditStarted`       | Ticket 34's durable audit adapter. Resolve only after ingest or shared buffering succeeds; reject if neither succeeds. Honor the remaining deadline. Never log meal arguments, tokens or credentials.                                                                                                  |

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
  Bigint IDs remain strings. Only `{ "id": "...", "status": "recorded" }` is cached
  and returned on both first success and replay. The full meal is shown in the
  preview, not retained in the confirmation result. Responses over 32 KiB are refused.
- Pending calls return a preview; another live claim returns `in_progress` and
  `retry_after_ms`. A completed confirmation returns the same cached `recorded`
  result, after fresh authorization checks, without another backend call.
- A timeout or lost/malformed response can follow a committed database write.
  Retry **the same token and exact meal** after the lease, so Ticket 47 returns the
  original row. The HTTP adapter performs no automatic write retry. Never issue
  a new confirmation merely to recover an uncertain write.
- The handler sends the trusted remaining request budget as `requestDeadlineMs`.
  The writer uses the smaller `deadlineMs` returned after Redis claim and consumes
  that same budget across credential exchange, live authorization and the HTTP
  write. A request that exceeds the configured lease is refused before claiming.
- Changed arguments, unknown tokens and expired pending confirmations return the
  existing `confirmation_required` response with an empty token; they never issue
  a replacement automatically. Both text and structured output use the model-safe
  payload. Mismatch details remain available on `ConfirmationError.toLog()` and
  are not included in the model response. Backend 409 uses the same refusal;
  400 is invalid input; 401 and 403
  retain authentication/scope semantics. Unavailability stays retryable, including
  Ticket 47's current default 503 until its authentication adapter is integrated.

## Reproducible checks

Use Node 24 and run:

```sh
npm ci
npm run validate
npm run build
```

For the real Redis suites, use a disposable local database. With Docker Desktop
running, the following PowerShell commands also work on Windows:

```powershell
docker run --detach --rm --name nutrihelp-ticket49-redis -p 127.0.0.1:16379:6379 redis:7-alpine
$env:MCP_CONFIRMATION_TEST_REDIS_URL = "redis://127.0.0.1:16379"
npm.cmd run test:integration
docker stop nutrihelp-ticket49-redis
```

The tests reject non-local Redis URLs and delete only their own confirmation keys.
`npm test` includes the tool, verified-context and HTTP-adapter unit tests without
Redis. `npm run test:integration` covers the confirmation store and actual MCP
HTTP tool flow, including two independent server/store instances, concurrency,
revocation, minimal cached receipts and response-loss recovery. Missing Redis
configuration explicitly skips both suites with a reason. Empty, malformed or
unreachable configured URLs fail. CI supplies a disposable Redis service.

No extra multi-file test shortcuts are added: the standard repository commands
collect the unit and integration suites. The live configuration must maintain
`leaseMs > requestDeadlineMs`; raising the transport timeout requires adjusting
the store configuration too.

The repository also contains existing failing security suites for unfinished
features. In particular, the old consent fixture starts an empty registry and
uses the old `items` shape. It is not silently skipped or weakened by this change.
The new `test/integration/recordMeal.test.ts` runs the actual registry and current
Ticket 47 snapshot contract.

## Local verification

Verified on Node 24.19.0 with Ticket 48 base `4b1d1f5` and Redis 7.4.8:

| Check                                          | Result                                                                      |
| ---------------------------------------------- | --------------------------------------------------------------------------- |
| `npm run validate` and `npm run build`         | Passed                                                                      |
| Unit tests                                     | 838 passed, including 82 for the record-meal tool, context and HTTP adapter |
| Protocol conformance                           | 83 passed                                                                   |
| Egress, upstream mock and composition controls | 147 passed                                                                  |
| Redis integration                              | 41 passed: 27 confirmation-store and 14 record-meal tests                   |
| Missing Redis URL                              | Both suites explicitly skipped with a reason (41 skipped)                   |
| Configured empty Redis URL                     | Both suites failed setup with nonzero exit, as required                     |
| Full security suite                            | 189 passed, 5 failed; the same five were reproduced on clean main `e96e600` |
| Dependency audit                               | High-severity gate passed; 3 moderate Vitest dependency advisories remain   |

The five existing failures are the two confirmation fixtures whose tool calls
return 404, the meal-plan response and registry fixtures, and the upstream test
whose substring assertion matches Node's `user-agent` header. No security tests
were deleted or skipped to make this branch pass.

Redis tests run the real store and Lua scripts. Backend HTTP, credential exchange
and audit adapters are controlled by test fixtures; these results do not verify
the deployed MCP-to-backend flow. GitHub Actions results must be checked after push.
