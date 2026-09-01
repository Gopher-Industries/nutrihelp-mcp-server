# nutrihelp-mcp-server

A Model Context Protocol server that lets a NutriHelp user connect their account to an external
AI assistant. It speaks MCP over Streamable HTTP to assistants and authenticated HTTPS to exactly
one backend. It holds no database credential, never contacts Supabase, and owns no business
logic.

## Status

Early. The transport is real and the rest is not yet built.

| Area                                | State                                                                                     |
| ----------------------------------- | ----------------------------------------------------------------------------------------- |
| `/mcp` endpoint                     | Reachable. Protocol revision `2026-07-28` selected exclusively.                           |
| Origin validation                   | Enforced against an explicit allowlist.                                                   |
| Authentication                      | Enforced against published JWKS. Algorithm, issuer, audience and token type pinned.       |
| Discovery                           | Protected resource metadata is served, and the `WWW-Authenticate` challenge points at it. |
| Live grant introspection            | **Not implemented.** Expiry is the only bound on a leaked token today.                    |
| Tools                               | **None registered.** `tools/list` returns `-32601`.                                       |
| Lint, format, test, coverage, hooks | Installed. `npm run validate` runs them.                                                  |

Because no tool is registered, this service currently exposes no NutriHelp data. Do not deploy it
publicly in this state.

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

Eight variables are read today. All eight are required and none of them defaults: a missing one
stops the process at startup rather than being filled in.

| Variable                  | Description                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `PORT`                    | The port to listen on. Render injects it.                                                                     |
| `MCP_ALLOWED_ORIGINS`     | Comma-separated origin allowlist. An explicit list, not a regex, not a wildcard.                              |
| `MCP_JWKS_URL`            | Where verification keys are fetched from. **`https:` only**, with no exemption for loopback.                  |
| `MCP_EXPECTED_ISSUER`     | The `iss` claim a token must carry. `https:` only. Stored verbatim — it is compared byte for byte.            |
| `MCP_AUTH_SERVER_URL`     | The authorization server this service names in its public metadata. `https:`, no userinfo, query or fragment. |
| `MCP_RESOURCE_IDENTIFIER` | This server's canonical identifier, including its path. Also the expected audience. `https:`, normalised.     |
| `MCP_JWKS_CACHE_TTL_S`    | How long a fetched key set may be reused, in seconds. Between 60 and 86400.                                   |
| `MCP_REQUEST_DEADLINE_MS` | The end-to-end deadline for one request, in milliseconds. Not a per-call timeout. At most 600000.             |

`MCP_ALLOWED_ORIGINS` entries are parsed as URLs and reduced to hostnames; the guard is
port-agnostic. A malformed entry fails startup rather than being skipped.

`MCP_EXPECTED_ISSUER` and `MCP_AUTH_SERVER_URL` are different values that usually look the same,
and confusing them is a real failure: one is checked against a claim, the other is published to
anyone who reads the discovery document.

More variables land as each module does; these eight are what the current tree reads. Values come
from the service environment, or from a `.env` file that never overrides one already set. There is no `.env.example`, on purpose — the local values are written out below rather than
kept in a second file that drifts. `JWT_TOKEN`, `SUPABASE_URL` and `SUPABASE_ANON_KEY` are absent
by construction and are not to be added.

## Local development without a backend

Nothing here needs the NutriHelp backend. It does need an authorization server, because the
server will not verify a token without a reachable key set, and that key set must be served over
`https:` — there is no loopback exemption and there will not be one. So a local run stands up a
small issuer beside the server.

`npm run token:test` does all of it from **one RS256 key pair**: it generates the pair on first
run and reuses it afterwards, serves it as a JWKS document over local HTTPS, and prints an access
token signed by that same key. One key pair is the point — a rejected token can then only mean the
token is wrong, never that a different key was served.

Everything it writes goes to `.dev/`, which is git-ignored: a private signing key, a TLS key and a
token all live there. Nothing in that directory is ever committed.

**The commands in this section are `bash`.** On Windows that means Git Bash, which ships with Git
for Windows and so is on any machine that cloned this repository — and which is also where
`openssl` comes from, since PowerShell carries none. The few lines that behave differently under
PowerShell carry a PowerShell form where they appear.

### 1. Write a `.env`

```bash
PORT=3000
MCP_ALLOWED_ORIGINS=http://localhost:6274,http://127.0.0.1:6274
MCP_JWKS_URL=https://127.0.0.1:8443/jwks
MCP_EXPECTED_ISSUER=https://127.0.0.1:8443
MCP_AUTH_SERVER_URL=https://127.0.0.1:8443
MCP_RESOURCE_IDENTIFIER=https://localhost:3000/mcp
MCP_JWKS_CACHE_TTL_S=60
MCP_REQUEST_DEADLINE_MS=10000
```

Two of these look wrong and are not. `MCP_RESOURCE_IDENTIFIER` is `https:` while the dev server
listens on `http:`, because it is an identifier and an audience rather than an address anything
dials. And the issuer URLs use `127.0.0.1` rather than `localhost`, so nothing depends on which
address family `localhost` happens to resolve to first.

The Inspector's browser client sends its own origin, which is why `6274` appears in the allowlist.
The port in that value is decorative — entries are reduced to hostnames — but writing the origin
out in full is what the variable is for.

### 2. Generate a certificate for the issuer

Self-signed, into `.dev/`, never committed. Both names matter: the certificate has to cover the
host in `MCP_JWKS_URL`, and it has to be usable as its own trust anchor.

```bash
mkdir -p .dev
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout .dev/tls-key.pem -out .dev/tls-cert.pem -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:TRUE"
```

`MSYS_NO_PATHCONV=1` is inert on Linux and macOS and load-bearing under Git Bash, where MSYS
otherwise rewrites the leading slash of `-subj "/CN=localhost"` into a Windows path and `openssl`
exits 1 complaining that the subject name is not in the expected format. Do not reach for the
`-subj "//CN=localhost"` workaround instead: on OpenSSL 3 that exits 0, warns
`Skipping unknown subject name attribute`, and hands back a certificate with an empty subject.

The same block in PowerShell, which continues a line with a backtick rather than a backslash and
rewrites no paths:

```powershell
New-Item -ItemType Directory -Force .dev
openssl req -x509 -newkey rsa:2048 -nodes `
  -keyout .dev/tls-key.pem -out .dev/tls-cert.pem -days 365 `
  -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" `
  -addext "basicConstraints=critical,CA:TRUE"
```

If PowerShell cannot find `openssl`, Git for Windows bundles one at `C:\Program Files\Git\usr\bin`.

#### Then protect the directory

`.dev/` holds two secrets, and they are not the same kind of thing:

- **`.dev/tls-key.pem`**, the private key of the certificate above. `CA:TRUE` plus step 4 makes that
  certificate a trust anchor the dev process honours for **every** outbound TLS connection it opens,
  not just the key set fetch, so whoever holds this key can impersonate any host to that process.
- **`.dev/signing-key.json`**, the RS256 key `npm run token:test` signs with. Whoever holds it can
  mint a token this server accepts. `openssl` writes the first; the issuer script writes the second,
  which is how a recipe that protected only the `openssl` output left the more directly useful of the
  two readable by every local account.

`.dev/inspector.json` carries a live token minted by the second key, so it is worth the same care.

Protect the **directory**, not a list of files. Four files land in `.dev/` between step 2 and step
3, and more will as this server grows; a list of them has to be maintained by hand and is wrong on
the day a fifth appears, whereas the directory is a boundary that cannot drift.

On Linux and macOS one line does it:

```bash
chmod 700 .dev
```

`openssl` and the issuer both leave their files mode 644. Mode 700 on the directory withholds the
traverse bit from everyone else, so no other local account can open a path through it — including
files written later. The files keep their own 644, so the directory _is_ the protection: a key
copied out of `.dev/` leaves it behind.

**On Windows that line does nothing, and running it is worse than skipping it** — it exits 0 and
leaves you believing the directory is protected. Git for Windows mounts every drive `noacl`, so
`chmod 700` succeeds silently and `ls -ld .dev` still reports `drwxr-xr-x`. What actually governs
the directory is the NTFS access list it inherits from above, and a checkout outside your own
profile typically inherits an entry like `BUILTIN\Users:(I)(RX)` — every local account can read both
keys. Replace the inherited list with your own account:

```bash
# Git Bash
MSYS_NO_PATHCONV=1 icacls .dev /inheritance:r /grant:r "$USERNAME:(OI)(CI)(F)"
```

```powershell
# PowerShell
icacls .dev /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)(F)"
```

`/inheritance:r` drops the inherited entries rather than adding beside them, and `/grant:r` replaces
any explicit entry for that account rather than merging into it. `(OI)(CI)` is what carries the
grant down: dropping the parent's inheritable entries propagates into the files already in `.dev/`,
and anything written there afterwards inherits your entry alone. `(F)` rather than `(R,W)` because
this is a directory you own and keep rewriting — the issuer replaces files in it on every run.

Check both halves, because only the directory was named:

```bash
MSYS_NO_PATHCONV=1 icacls .dev
MSYS_NO_PATHCONV=1 icacls .dev/tls-key.pem
```

Your account should be the only line in each — `(OI)(CI)(F)` on the directory, `(I)(F)` on the file.
The file is the half worth looking at, because it existed before the directory was stamped: seeing
`(I)(F)` alone on it is what proves the inherited `BUILTIN\Users:(I)(RX)` is gone rather than still
sitting on a key that was already there. The listing drops the SYSTEM and Administrators entries
too, which changes nothing an administrator could not already do by taking ownership. Unlike the
`openssl` block above, `MSYS_NO_PATHCONV=1` is precautionary here rather than load-bearing:
`/inheritance:r` and `/grant:r` carry a colon, so MSYS leaves them alone with or without it.

`.dev/signing-key.json` is not checked here because it does not exist yet — the issuer writes it in
step 3, and step 3 checks it there.

**Do not reach for `/T` to force that propagation.** It applies the same operation to every file
underneath, and on a file `(OI)(CI)` are container-inheritance flags that grant nothing: `/grant:r`
lands nowhere while `/inheritance:r` strips the inherited entries, leaving the key with an empty
access list that not even you can read or rewrite, and leaving the issuer unable to replace its own
files on the next run. It would also make `MSYS_NO_PATHCONV=1` load-bearing here, since a bare `/T`
has no colon and MSYS rewrites it to `T:/`.

### 3. Run the issuer, and leave it running

```bash
npm run token:test
```

It prints the key set address, the issuer, the audience and a token valid for one hour, and it
writes an Inspector session config to `.dev/inspector.json` carrying that same token.

On Windows, this is the point at which the signing key exists, so this is where it can be checked:

```bash
MSYS_NO_PATHCONV=1 icacls .dev/signing-key.json
```

Your account with `(I)(F)`, and nothing else. The `(I)` is the whole point — this file was created
after step 2 stamped the directory, so an inherited-only entry is what shows that a file written
later still lands protected without the recipe naming it. That matters more here than for the TLS
key: whoever holds this one can mint a token this server accepts.

### 4. Run the server, told to trust that certificate

```bash
NODE_EXTRA_CA_CERTS=.dev/tls-cert.pem npm run dev
```

In PowerShell that prefix is not a thing, so set it first:
`$env:NODE_EXTRA_CA_CERTS = '.dev/tls-cert.pem'; npm run dev`.

Without it the key set fetch fails and **every** token is answered `503`, with
`upstream_failure.key_set_unreachable` in the log — the key set could not be consulted, so nothing
is known about the credential and it is not treated as the token's fault. Reach for
`NODE_EXTRA_CA_CERTS` and not `NODE_TLS_REJECT_UNAUTHORIZED=0`: the second one disables
certificate verification for the whole process, including the calls this server makes outbound.

### 5. Check it

In a third terminal. `TOKEN` is the string the issuer printed — or read it back out of the
Inspector config it wrote, which is the same token:

```bash
TOKEN=$(node -p "require('./.dev/inspector.json').mcpServers.nutrihelp.headers.Authorization.slice(7)")
```

```powershell
$TOKEN = node -p "require('./.dev/inspector.json').mcpServers.nutrihelp.headers.Authorization.slice(7)"
```

```bash
# the discovery document — public, no token
curl -s http://localhost:3000/.well-known/oauth-protected-resource/mcp

# no token: 401 with a challenge naming that document
curl -s -i -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}}}}'

# with the printed token: 404 / -32601, which is PAST authentication
curl -s -i -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}}}}'
```

`404` with `-32601` is the correct result today: the token was accepted and dispatch found no
tool, because none is registered. A `401` there means the token was refused; the server log names
which check refused it.

The same three checks in PowerShell. The envelope is built once as a hashtable and handed to
`ConvertTo-Json`, so there is no quoting to get wrong:

```powershell
$body = @{
  jsonrpc = '2.0'
  id      = 1
  method  = 'tools/list'
  params  = @{
    _meta = @{
      'io.modelcontextprotocol/protocolVersion'    = '2026-07-28'
      'io.modelcontextprotocol/clientCapabilities' = @{}
    }
  }
} | ConvertTo-Json -Depth 6

$headers = @{
  'Accept'               = 'application/json, text/event-stream'
  'MCP-Protocol-Version' = '2026-07-28'
  'Mcp-Method'           = 'tools/list'
}

# the discovery document — public, no token
Invoke-RestMethod http://localhost:3000/.well-known/oauth-protected-resource/mcp | ConvertTo-Json

# no token: 401 with a challenge naming that document
try {
  Invoke-WebRequest -Method Post -Uri http://localhost:3000/mcp `
    -Headers $headers -ContentType 'application/json' -Body $body -UseBasicParsing
} catch {
  $r = $_.Exception.Response
  "$([int]$r.StatusCode) $($r.StatusDescription)"
  "WWW-Authenticate: $($r.Headers['WWW-Authenticate'])"
}

# with the printed token: 404 / -32601, which is PAST authentication
$authed = $headers.Clone()
$authed['Authorization'] = "Bearer $TOKEN"
try {
  Invoke-WebRequest -Method Post -Uri http://localhost:3000/mcp `
    -Headers $authed -ContentType 'application/json' -Body $body -UseBasicParsing
} catch {
  $r = $_.Exception.Response
  "$([int]$r.StatusCode) $($r.StatusDescription)"
  (New-Object System.IO.StreamReader($r.GetResponseStream())).ReadToEnd()
}
```

`Invoke-WebRequest` throws on any non-2xx status, so both of the answers this step is looking for
arrive as exceptions rather than as return values. That is what the `try`/`catch` is for:
`$_.Exception.Response` carries the status and the `WWW-Authenticate` header, and the JSON-RPC body
has to be pulled off the response stream with a `StreamReader` because it is not buffered onto the
exception. A bare `Invoke-WebRequest` with no `catch` reports `The remote server returned an error:
(401) Unauthorized.` and throws the challenge away, which is the one part worth reading.

The native cmdlets are given rather than `curl.exe` because that is where this goes wrong under
PowerShell. Bare `curl` is an alias for `Invoke-WebRequest`, which binds `-s` to its own
`-SessionVariable` and fails on a missing argument before anything is sent, so the `bash` lines
above need `curl.exe` spelled out in full, plus backticks for the line continuations — and then
PowerShell 5.1 strips the quotes out of a native command's arguments and puts `{jsonrpc:2.0,...}`
on the wire unless every quote inside `-d` is backslash-escaped. `ConvertTo-Json` over a hashtable
has no quoting step to get wrong.

### 6. The Inspector

```bash
npm run inspect
```

That opens the web UI on `http://localhost:6274` with `.dev/inspector.json` preloaded. Toggle the
`nutrihelp` server on; it reports **Connected** and `MCP 2026-07-28`.

For a headless check, the same config drives the CLI:

```bash
npx mcp-inspector --cli --config .dev/inspector.json --server nutrihelp --method initialize
```

which answers with this server's own name, version and negotiated protocol revision. Use
`initialize` rather than `tools/list` for this. The raw endpoint answers `tools/list` with
`-32601`, as step 5 showed, but the Inspector absorbs that and reports `{"tools": []}` — which is
also what it reports for a client that never connected at all. An empty list is therefore not
evidence of anything, and must never be read as a passing check.

Two things in `.dev/inspector.json` are load-bearing, and both are why the Inspector is driven
from a config file rather than from flags:

- `"protocolEra": "modern"`. The Inspector defaults to the legacy era, which this server rejects
  with `-32022 Unsupported protocol version`. There is no command-line flag for it — the setting
  exists only in the config file. (`"auto"` also reaches the modern leg and was checked; `"modern"`
  is what the generated file writes, because it says what is intended.)
- The bearer token sits in `headers`, not on `--header`. The web client refuses `--header`
  alongside `--config`, so putting the token in the file is what makes one recipe serve the web UI
  and the CLI alike. Without a token the CLI does not fail with a `401`: it fails at version
  negotiation, saying the server did not offer `2026-07-28`, because the `401` is buried inside
  the connect probe.

The token expires after an hour. Stop the issuer and re-run `npm run token:test` for a fresh one:
the key pair is reused, so the MCP server needs no restart and the Inspector config is rewritten
in place. Re-running it while the first issuer still holds the port refuses to start, says so, and
changes nothing — the old token stays valid until it expires.

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
npm run test:controls    # the control files that validate chains, one invocation each
npm run test:integration # needs a backend that does not exist yet
npm run coverage         # vitest run --coverage

npm run token:test       # local issuer: serves the key set, prints a token. Leave it running
npm run inspect          # MCP Inspector against .dev/inspector.json

npm run validate         # check:node + typecheck + lint + format:check + test + conformance
                         #   + test:controls + security:audit
```

`validate` is what the husky `pre-push` hook runs. It is not full CI parity and does not claim to
be: coverage, secret scanning, `test:security` and `test:integration` are not chained into it.
Run `npm run coverage` before opening a pull request that touches the auth or tool directories,
and `npm run test:security` for any change to the authorization path.

## Calling the endpoint

Protocol revision `2026-07-28` is selected exclusively — 2025-era traffic is rejected rather than
served. That revision asks for more than a bare JSON-RPC body, and a request missing any of it
fails before dispatch. Five things are required together:

1. `Authorization: Bearer <token>`. Absent, `401` with a `WWW-Authenticate` challenge naming the
   discovery document. See "Local development without a backend" above for where a token comes
   from.
2. `MCP-Protocol-Version: 2026-07-28` as a header. Absent, you get `-32022`.
3. An `Mcp-Method` header naming the same method as the body. Mismatched or absent, `-32020`.
4. A `params._meta` envelope carrying `io.modelcontextprotocol/protocolVersion` and
   `io.modelcontextprotocol/clientCapabilities`. Absent, `-32602` naming the missing keys.
5. `Accept: application/json, text/event-stream`, for Streamable HTTP.

A real MCP client sends all five for you. The reason to write them down is that hand-testing with
`curl` fails five times in a row otherwise, each with a different error code, and the errors do
not obviously point at one another. This is `bash` again — see the note at the end of step 5 for
what PowerShell does to it.

```bash
curl -s -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
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
- **No `.env.example`.** The variables and a working set of local values are written out under
  Configuration and "Local development without a backend" instead. A second file listing the same
  names goes stale silently, and the one place people look for a name is the prose that explains
  what it does.
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
