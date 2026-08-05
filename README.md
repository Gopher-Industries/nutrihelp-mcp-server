# NutriHelp MCP Server

MCP server exposing NutriHelp backend and AI functionality as tools for LLM clients (Claude, etc.)

## Setup

npm install
npm run build
npm start

Server runs on http://localhost:3000/mcp using Streamable HTTP transport.

## Testing locally with Claude.ai (via ngrok)

1. Run the server: `npm start`
2. In a separate terminal: `ngrok http 3000`
3. Copy the ngrok HTTPS URL, append `/mcp`
4. In Claude.ai: Settings > Connectors > Add custom connector > paste URL
5. Enable the connector in a chat and test the `ping` tool

## Authentication

The MCP server must not connect directly to Supabase or hold Supabase
credentials. NutriHelp data is accessed only through the NutriHelp backend API.

The current integration forwards the request's bearer token to the NutriHelp
backend, which remains responsible for protecting its API. MCP-specific token
verification is tracked separately and is not implemented by a Supabase client
in this server.

## Tools

- `ping` — test tool, returns a static string, no auth/data access
- `get_meal_plan` — forwards the current request's bearer token to the
  NutriHelp backend and returns that backend's response

## Testing locally (without Claude)

You can test the backend integration directly via PowerShell's
`Invoke-RestMethod`, without needing a Claude connector.

1. Register a test user against the NutriHelp backend:
```powershell
$body = @{ name="Test"; email="test@example.com"; password="Test@1234"; contact_number="0412345678"; address="123 Test St" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8081/api/auth/register" -Method POST -ContentType "application/json" -Body $body
```
2. Log in to get a token:
```powershell
$loginBody = @{ email="test@example.com"; password="Test@1234" } | ConvertTo-Json
$response = Invoke-RestMethod -Uri "http://localhost:8081/api/auth/login" -Method POST -ContentType "application/json" -Body $loginBody
$token = $response.data.session.access_token
```

3. Call the MCP server with the token (note: both `Authorization` and `Accept` headers are required):
```powershell
$mcpBody = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_meal_plan","arguments":{}}}'
Invoke-RestMethod -Uri "http://localhost:3000/mcp" -Method POST -Headers @{"Authorization"="Bearer $token"; "Accept"="application/json, text/event-stream"} -ContentType "application/json" -Body $mcpBody
```
