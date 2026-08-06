# nutrihelp-mcp-server

A Model Context Protocol server that lets a NutriHelp user connect their account to an external
AI assistant. It speaks MCP over Streamable HTTP to assistants and authenticated HTTPS to exactly
one backend. It holds no database credential, never contacts Supabase, and owns no business
logic.

## Status

Early. The transport is real and the rest is not yet built.

| Area                                | State                                                           |
| ----------------------------------- | --------------------------------------------------------------- |
| `/mcp` endpoint                     | Reachable. Protocol revision `2026-07-28` selected exclusively. |
| Origin validation                   | Enforced against an explicit allowlist.                         |
| Tools                               | **None registered.** `tools/list` returns `-32601`.             |
| Authentication                      | **Not implemented.** No token is validated yet.                 |
| Lint, format, test, coverage, hooks | Installed. `npm run validate` runs them.                        |

Because no tool is registered and no authentication runs, this service currently exposes no
NutriHelp data. Do not deploy it publicly in this state.

## Requirements

Node 24 LTS, pinned in `engines.node` and `.node-version`. Node 22 sits at the exact floor for
type stripping and the MCP Inspector, so a loose `22` pin breaks both silently. Newer majors are
outside the `engines` range.

## Setup

```bash
npm install
npm run dev
```

`npm run dev` runs the TypeScript entrypoint directly through Node's type stripping. There is no
build step and no watcher to run alongside it. This works because of `verbatimModuleSyntax` plus
`erasableSyntaxOnly`, and it keeps working only while `erasableSyntaxOnly` stays on — it fails
the build the moment someone writes an `enum` or a constructor parameter property. Do not
disable it.

## Configuration

Configuration is validated at startup and the process refuses to start on a missing or malformed
value. Nothing security-relevant defaults.

Two variables are read today, because they are the only two the transport needs:

| Variable              | Required | Description                                                                      |
| --------------------- | -------- | -------------------------------------------------------------------------------- |
| `PORT`                | Yes      | The port to listen on. Render injects it.                                        |
| `MCP_ALLOWED_ORIGINS` | Yes      | Comma-separated origin allowlist. An explicit list, not a regex, not a wildcard. |

`MCP_ALLOWED_ORIGINS` entries are parsed as URLs and reduced to hostnames; the guard is
port-agnostic. A malformed entry fails startup rather than being skipped.

The full set of variables the finished service takes is fixed by the implementation plan and is
added as each module lands. `JWT_TOKEN`, `SUPABASE_URL` and `SUPABASE_ANON_KEY` are absent by
construction and are not to be added.

## Commands

```bash
npm run dev              # node --watch on the TypeScript entrypoint, no build step
npm run build            # tsc -p tsconfig.build.json  ->  dist/
npm start                # node dist/server.js

npm run typecheck        # tsc --noEmit
npm run lint             # eslint .
npm run format:check     # prettier --check .   (npm run format rewrites)

npm test                 # unit
npm run conformance      # protocol conformance
npm run test:security    # security suite
npm run test:integration # needs a backend that does not exist yet
npm run coverage         # vitest run --coverage

npm run validate         # typecheck + lint + format:check + test + conformance + audit
```

`validate` is what the husky `pre-push` hook runs. It is not full CI parity and does not claim to
be: coverage, secret scanning, `test:security` and `test:integration` are not chained into it.
Run `npm run coverage` before opening a pull request that touches the auth or tool directories,
and `npm run test:security` for any change to the authorization path.

## Calling the endpoint

Protocol revision `2026-07-28` is selected exclusively — 2025-era traffic is rejected rather than
served. That revision asks for more than a bare JSON-RPC body, and a request missing any of it
fails before dispatch. Four things are required together:

1. `MCP-Protocol-Version: 2026-07-28` as a header. Absent, you get `-32022`.
2. An `Mcp-Method` header naming the same method as the body. Mismatched or absent, `-32020`.
3. A `params._meta` envelope carrying `io.modelcontextprotocol/protocolVersion` and
   `io.modelcontextprotocol/clientCapabilities`. Absent, `-32602` naming the missing keys.
4. `Accept: application/json, text/event-stream`, for Streamable HTTP.

A real MCP client sends all four for you. The reason to write them down is that hand-testing with
`curl` fails four times in a row otherwise, each with a different error code, and the errors do
not obviously point at one another.

```bash
curl -s -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
      }
    }
  }'
```

Against the current scaffold that returns `-32601 Method not found`, because no tool is
registered. That is the expected response today, not a misconfiguration.

There is no `initialize` handshake, no session identifier and no sticky routing. Every request
stands alone.

### Origin policy

| `Origin` header                            | Result     |
| ------------------------------------------ | ---------- |
| Absent                                     | Allow      |
| Empty string                               | Allow      |
| Present, hostname on the allowlist         | Allow      |
| Present, hostname not on the allowlist     | Reject 403 |
| Present, malformed or the literal `"null"` | Reject 403 |

Absent and empty-string pass because non-browser MCP clients do not send an `Origin`. A browser
sends a real origin or the literal `null`, never an empty one.

## Deliberately absent

These are decisions, not gaps. Re-adding any of them reverses a design decision rather than
filling a hole.

- **No Supabase.** No client, no `SUPABASE_URL`, no `SUPABASE_ANON_KEY`. Every piece of NutriHelp
  data is reached through the backend over authenticated HTTPS. There is no exception for reads,
  for performance, for local development, or for a test.
- **No `JWT_TOKEN` and no shared symmetric secret.** Inbound tokens are verified against
  published JWKS with the algorithm list, issuer, audience and type all pinned. This server
  verifies against a public key and mints nothing.
- **No ngrok tunnel.** Public access goes through a proper deployment with login. A tunnel to a
  development instance sits outside the origin allowlist and the rate limits.
- **No `.npmrc`.** `legacy-peer-deps` would silently swallow the TypeScript peer-range conflict
  and install a lint stack that cannot parse the code, producing a lint job that runs, reports
  green, and checks nothing.
- **No second HTTP client.** Outbound calls go through one module, so the identity deny-list and
  the credential attachment cannot be bypassed.

## Design documents

The implementation plan, architecture, code style, testing policy and execution log are held by
the team and tracked on the MS Teams Planner board. They are deliberately not committed to this
repository, so a fresh clone does not carry them — ask the MCP team lead rather than
reconstructing intent from the code.
