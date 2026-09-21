# nutrihelp-mcp-server

A Model Context Protocol server that lets a NutriHelp user connect their account to an external
AI assistant. It speaks MCP over Streamable HTTP to assistants and authenticated HTTPS to exactly
one backend. It holds no database credential, never contacts Supabase, and owns no business
logic.

## Status

Early. The transport is real and the rest is not yet built.

| Area                                | State                                                                                                                                                |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/mcp` endpoint                     | Reachable. Protocol revision `2026-07-28` selected exclusively.                                                                                      |
| Origin validation                   | Enforced against an explicit allowlist.                                                                                                              |
| Authentication                      | Token validated offline against published JWKS — algorithm, issuer, audience and token type pinned — then live grant introspection on every request. |
| Discovery                           | Protected resource metadata is served, and the `WWW-Authenticate` challenge points at it.                                                            |
| Tools                               | One registered: `nutrition_lookup`.                                                                                                                  |
| Lint, format, test, coverage, hooks | Installed. `npm run validate` runs them.                                                                                                             |

Authentication is wired but **not yet operable**: introspection calls an authorization server that
does not exist yet and fails closed, so every authenticated request is refused until that endpoint
ships. Do not deploy it publicly in this state.

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

Twelve variables are read today. Eleven are required and none of them defaults: a missing one
stops the process at startup rather than being filled in.

| Variable                        | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PORT`                          | Yes      | The port to listen on. Render injects it.                                                                                                                                                                                                                                                                                                                                                                                                        |
| `MCP_ALLOWED_ORIGINS`           | Yes      | Comma-separated origin allowlist. An explicit list, not a regex, not a wildcard.                                                                                                                                                                                                                                                                                                                                                                 |
| `NUTRIHELP_API_BASE_URL`        | Yes      | Base URL of the NutriHelp backend API. **`https:` only** — over cleartext it could be substituted in transit.                                                                                                                                                                                                                                                                                                                                    |
| `MCP_JWKS_URL`                  | Yes      | Where verification keys are fetched from. **`https:` only**, with no exemption for loopback.                                                                                                                                                                                                                                                                                                                                                     |
| `MCP_EXPECTED_ISSUER`           | Yes      | The `iss` claim a token must carry. `https:` only. Stored verbatim — it is compared byte for byte.                                                                                                                                                                                                                                                                                                                                               |
| `MCP_AUTH_SERVER_URL`           | Yes      | The authorization server this service names in its public metadata, and the base of the introspection endpoint. `https:`, no userinfo, query or fragment.                                                                                                                                                                                                                                                                                        |
| `MCP_RESOURCE_IDENTIFIER`       | Yes      | This server's canonical identifier, including its path. Also the expected audience. `https:`, normalised.                                                                                                                                                                                                                                                                                                                                        |
| `MCP_JWKS_CACHE_TTL_S`          | Yes      | How long a fetched key set may be reused, in seconds. Between 60 and 86400.                                                                                                                                                                                                                                                                                                                                                                      |
| `MCP_REQUEST_DEADLINE_MS`       | Yes      | The end-to-end deadline for one request, in milliseconds. Not a per-call timeout. At most 600000.                                                                                                                                                                                                                                                                                                                                                |
| `MCP_CLIENT_ID`                 | Yes      | This server's own client identifier at the authorization server — `iss` and `sub` of every client assertion. An `https:` URL with a **non-empty path**, and it **must differ from `MCP_RESOURCE_IDENTIFIER`**: resource and client are separate registrations there, and the process refuses to start if the two match. Stored verbatim, never normalised, because the authorization server compares it as a string against what was registered. |
| `MCP_CLIENT_ASSERTION_KEY`      | Yes      | This server's own private key, PKCS#8 PEM, for `private_key_jwt` at the introspection and exchange endpoints. Parsed at startup, so an unreadable key stops the process instead of surfacing as an outage on the first request. RSA or EC: startup accepts any asymmetric key, but only those two can sign an assertion, so another type fails on the first request instead.                                                                     |
| `MCP_REVOKED_GRANT_CACHE_TTL_S` | No       | How long an already-inactive grant may be refused from cache, in seconds. Up to 300; **defaults to 0**, meaning ask every time. It never caches an active answer and never permits a call, so it can only ever refuse faster.                                                                                                                                                                                                                    |

`MCP_ALLOWED_ORIGINS` entries are parsed as URLs and reduced to hostnames; the guard is
port-agnostic. A malformed entry fails startup rather than being skipped.

`MCP_EXPECTED_ISSUER` and `MCP_AUTH_SERVER_URL` are different values that usually look the same,
and confusing them is a real failure: one is checked against a claim, the other is published to
anyone who reads the discovery document.

`MCP_CLIENT_ID` and `MCP_CLIENT_ASSERTION_KEY` are the pair used for `private_key_jwt` on every
live introspection (between token validation and scope). The key is this server's own credential,
never logged. **Both must be registered at the authorization server** before this server can serve
a request; an unreachable or unrecognised client fails closed rather than serving unchecked.

More variables land as each module does; these twelve are what the current tree reads. Values come
from the service environment, or from a `.env` file that never overrides one already set. There is no `.env.example`, on purpose — the local values are written out below rather than
kept in a second file that drifts. `JWT_TOKEN`, `SUPABASE_URL` and `SUPABASE_ANON_KEY` are absent
by construction and are not to be added.

## Local development without a backend

Nothing here needs the NutriHelp backend. It does need an authorization server, because the
server will not verify a token without a reachable key set, and that key set must be served over
`https:` — there is no loopback exemption and there will not be one. So a local run stands up a
small issuer beside the server.

> **This walkthrough starts the server, and stops short of a tool call.** After a token validates,
> the server asks the authorization server at `MCP_AUTH_SERVER_URL` whether the grant is still
> live. The local issuer below serves a key set and nothing else, so that question has no answer
> and every authenticated request is refused as an upstream failure (`503`) rather than reaching
> dispatch. Steps 1 to 4 and the unauthenticated checks in step 5 hold; the authenticated check in
> step 5 and all of step 6 need a running authorization server with introspection enabled and this
> server's client key registered there.

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

This block is the **contents** of a file, not commands to paste at a prompt. Create `.env` in the
repository root and put this in it:

```ini
PORT=3000
MCP_ALLOWED_ORIGINS=http://localhost:6274,http://127.0.0.1:6274
MCP_JWKS_URL=https://127.0.0.1:8443/jwks
MCP_EXPECTED_ISSUER=https://127.0.0.1:8443
MCP_AUTH_SERVER_URL=https://127.0.0.1:8443
MCP_RESOURCE_IDENTIFIER=https://localhost:3000/mcp
MCP_JWKS_CACHE_TTL_S=60
MCP_REQUEST_DEADLINE_MS=10000
MCP_CLIENT_ID=https://localhost:3000/client
NUTRIHELP_API_BASE_URL=https://127.0.0.1:9443
```

`MCP_CLIENT_ASSERTION_KEY` is required too and is deliberately not in this file. It is a private
key, so step 2 generates it into `.dev/` and step 4 hands it to the server from there.

Nothing listens on `NUTRIHELP_API_BASE_URL` in this recipe, and nothing needs to: every
authenticated request is refused at introspection before any backend call would be made.
`MCP_CLIENT_ID` has a path because the server refuses to start if it equals
`MCP_RESOURCE_IDENTIFIER` — client and resource are separate registrations.

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

Then this server's own client assertion key, the private key it signs `private_key_jwt` with. The
same line works in both shells:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .dev/client-assertion-key.pem
```

`genpkey` writes PKCS#8, the form this variable is documented to take. The server parses the key at
startup, so an unreadable one stops the process there rather than on the first request.

#### Then protect the directory

`.dev/` holds three secrets, and they are not the same kind of thing:

- **`.dev/tls-key.pem`**, the private key of the certificate above. `CA:TRUE` plus step 4 makes that
  certificate a trust anchor the dev process honours for **every** outbound TLS connection it opens,
  not just the key set fetch, so whoever holds this key can impersonate any host to that process.
- **`.dev/signing-key.json`**, the RS256 key `npm run token:test` signs with. Whoever holds it can
  mint a token this server accepts. `openssl` writes the first; the issuer script writes the second,
  which is how a recipe that protected only the `openssl` output left the more directly useful of the
  two readable by every local account.
- **`.dev/client-assertion-key.pem`**, this server's own client key. Whoever holds it can
  authenticate to the authorization server as this server.

`.dev/inspector.json` carries a live token minted by the signing key, so it is worth the same care.

Protect the **directory**, not a list of files. Five files land in `.dev/` between step 2 and step
3, and more will as this server grows; a list of them has to be maintained by hand and is wrong on
the day a sixth appears, whereas the directory is a boundary that cannot drift.

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
profile typically inherits `BUILTIN\Users:(I)(RX)` — every local account can read both keys.

**Do not go looking for that entry, though — it is rarely the only one and often not the worst.**
An inherited list can carry others that grant more: `NT AUTHORITY\Authenticated Users:(I)(M)` is
one such entry, and `(M)` is Modify, so an account holding it can rewrite the signing key rather
than merely read it. Which entries any particular checkout inherits depends on where it sits, so
**no list of names is the check** — hunting for this second name is the same mistake as hunting
for the first. The question is not _"is `BUILTIN\Users` present"_ but _"is anything other than me
present"_. Replace the inherited list with your own account:

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
Read it as a whole list and check that nothing else is on it; do not scan for a particular name,
for the reason above. The file is the half worth looking at, because it existed before the
directory was stamped: seeing `(I)(F)` **alone** on it is what proves the inherited entries are
gone rather than still sitting on a key that was already there. The listing drops the SYSTEM and
Administrators entries too, which changes nothing an administrator could not already do by taking
ownership. Unlike the
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
MCP_CLIENT_ASSERTION_KEY="$(cat .dev/client-assertion-key.pem)" \
  NODE_EXTRA_CA_CERTS=.dev/tls-cert.pem npm run dev
```

In PowerShell that prefix is not a thing, so set both first:

```powershell
$env:MCP_CLIENT_ASSERTION_KEY = Get-Content -Raw .dev/client-assertion-key.pem
$env:NODE_EXTRA_CA_CERTS = '.dev/tls-cert.pem'; npm run dev
```

The key goes in the environment, not in `.env`, so the private key stays inside the protected
directory. A value already in the environment wins over `.env`, so the two do not fight.

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

# with the printed token: 503 today, refused at introspection AFTER the token validated
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

`503` is the correct result in this setup: the token was accepted, and the live grant check that
follows could not be answered, because the local issuer serves no introspection endpoint. An
unanswerable check is the retryable class, never an authentication failure, so it is `503` rather
than `401`. A `401` there means the token itself was refused, or that a real authorization server
answered that the grant is no longer active. Against a running authorization server with this
server's client key registered, the same request returns `200` listing `nutrition_lookup`.

**The challenge that comes back with the `401` names a URL you cannot dial in this setup, and that
is not a fault.** It reads
`WWW-Authenticate: Bearer resource_metadata="https://localhost:3000/.well-known/oauth-protected-resource/mcp"`
— `https:`, because it is built from `MCP_RESOURCE_IDENTIFIER`, which step 1 explains is an
identifier and an audience rather than an address. The dev server listens on plain `http:`, so
dialling that URL verbatim fails the TLS handshake rather than returning the document
(`curl: (35) schannel: ... SEC_E_INVALID_TOKEN`, or `OpenSSL ... wrong version number`). Swap the
scheme to `http:` and it answers — which is what the first curl above already does. In a deployed
configuration the identifier and the address are the same URL and the challenge is dialable as
printed.

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

# with the printed token: 503 today, refused at introspection AFTER the token validated
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

That opens the web UI on `http://localhost:6274` with `.dev/inspector.json` preloaded. With only
the local issuer running, toggling the `nutrihelp` server on **does not connect**: the Inspector's
first request carries the token, so it meets the same live grant check as step 5 and gets `503`.
Against a running authorization server with this server's client key registered, it reports
**Connected** and `MCP 2026-07-28`.

For a headless check, the same config drives the CLI:

```bash
npx mcp-inspector --cli --config .dev/inspector.json --server nutrihelp --method initialize
```

which, once the grant check can be answered, returns this server's own name, version and
negotiated protocol revision. An empty tool list from the Inspector is not evidence of anything:
it also reports `{"tools": []}` for a client that never connected at all, so it must never be read
as a passing check. Evidence that the tool list works is a response the server actually sent,
naming `nutrition_lookup`.

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
npm run test:integration # real Redis; see Confirmation store below
npm run coverage         # vitest run --coverage

npm run token:test       # local issuer: serves the key set, prints a token. Leave it running
npm run inspect          # MCP Inspector against .dev/inspector.json

npm run validate         # check:node + typecheck + lint + format:check + test + conformance
                         #   + test:controls + security:audit
```

`validate` is what the husky `pre-push` hook runs. It is not full CI parity and does not claim to
be: coverage, secret scanning, `test:security` and `test:integration` are not chained into it.
Run `npm run coverage` before opening a pull request that touches the auth, consent or tool directories,
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

Sent as written, with no `Authorization` header, that returns `401` with a Bearer challenge. With a
valid token it is refused `503` until the authorization server's introspection endpoint exists —
see § Status. Both are the expected responses today, not misconfigurations.

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

## Confirmation store

The module at `src/consent/confirmation.ts` retains the `pending` / `in_progress` /
`done` state model. It accepts a local `{ eval }` port and does not import the
upstream client. `connectConfirmationStore` in `src/server.ts` opens the connection
and passes it to `createConfirmationStore`. Redis scripts are the authority for
claims and completion; no local fallback is used.

After rebasing onto main, run `npm ci` to install the locked dependencies, including
`@redis/client`, before typechecking. Importing the composition root for connection
tests does not start the HTTP server; `npm run dev` and `npm start` still do.

### Caller contract

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

### Tests

With Node 24 and Docker, from the repository directory (PowerShell):

```powershell
npm.cmd ci
docker run --detach --rm --name nutrihelp-ticket48-redis -p 127.0.0.1:16380:6379 redis:7-alpine
docker exec nutrihelp-ticket48-redis redis-cli ping
$env:MCP_CONFIRMATION_TEST_REDIS_URL = "redis://127.0.0.1:16380"
npm.cmd run validate
npm.cmd run test:integration
npm.cmd run test:security
npm.cmd run coverage
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

The coverage configuration requires at least 90% branch coverage for `src/consent/**`,
with the matching directory included in the coverage-policy guard. Report the full
coverage results alongside security failures; a known security failure is not a
green overall test run.
