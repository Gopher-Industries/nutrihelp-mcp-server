# Confirmation store

This module retains the existing `pending` / `in_progress` / `done` state model and
module layout. Redis scripts are the authority for claims and completion; no local
fallback is used.

## Caller contract

- Bind to verified user, assistant, connection and tool, and the exact validated arguments.
- Recheck live authorization before `execute`, including replay reads.
- Supply `requestDeadlineMs` on every execution from the trusted remaining request
  budget. It must be positive and strictly less than `leaseMs` (default 30 seconds).
  A missing or unsafe budget fails before a Redis claim or write.
- The writer receives `deadlineMs` after claim time has been deducted and must enforce
  that remaining budget on outbound calls. The store bounds its wait too, but cannot
  cancel a callback's external side effects. Backend idempotency remains required.
- Forward `idempotencyKeyHash` unchanged as the lowercase SHA-256 `Idempotency-Key`.
- Writers return an object with a string `id` (1–256 characters) and optionally a
  string `status` (1–64 characters). Only these fields are stored and returned, on
  first success and replay. Full meal details or personal fields are discarded.
  Invalid projected output becomes a sanitized upstream error and retains the
  uncertain-write recovery path. Existing full cached results are projected on read.

Errors extend the existing `McpError` taxonomy. Invalid inputs are `invalid_input`;
storage, writer, result and lost-attempt failures are `upstream_failure`. Invalid
or expired confirmations use `confirmation_required`. A binding/argument mismatch
has log-only `detailCode: confirmation_mismatch`, while an expired/unknown token
has `invalid_confirmation`; model payloads are identical and contain no submitted
token, identity or arguments. Callers should send `toLog()` to their existing audit
path, not raw exceptions.

Redis reconnects with up to eight retries and capped exponential delay plus jitter
(100–2099 ms). Commands during disconnection fail immediately and are never queued
for a later write. Explicit `close()` is terminal. After retry exhaustion the
composition layer must reconnect the store. A live lease is reported before
confirmation expiry, so an in-flight write is not incorrectly called expired.

## Tests

With Node 24 and Docker, from the repository directory (PowerShell):

```powershell
npm.cmd ci
docker run --detach --rm --name nutrihelp-ticket48-redis -p 127.0.0.1:16380:6379 redis:7-alpine
docker exec nutrihelp-ticket48-redis redis-cli ping
$env:MCP_CONFIRMATION_TEST_REDIS_URL = "redis://127.0.0.1:16380"
npm.cmd run validate
npm.cmd run test:integration
npm.cmd run test:security
docker stop nutrihelp-ticket48-redis
Remove-Item Env:MCP_CONFIRMATION_TEST_REDIS_URL
```

`test:integration` skips with an explicit reason only if the environment variable is
absent. An empty, malformed, non-local or unreachable configured URL is an error.
An empty test glob is also an error. The GitHub Actions workflow supplies its own
Redis service, so the real integration suite runs in CI.

The integration suite uses the production Lua scripts and independent connections.
It also executes two independently mutated scripts in Redis: one without the
binding/argument comparison and one without the `done` short-circuit. Each must
break its corresponding safety assertion. These fault-injection tests leave the
production scripts unchanged. The connection recovery test drops a TCP proxy's
sockets, checks fail-closed behavior, then restores connectivity to the same store.
Only keys created by this suite are deleted; no database flush is used.

The write callback is a simulated idempotent backend in these tests. Real Redis
coverage does not establish deployed backend integration. Existing security suite
failures must be reported separately from this suite's results.
