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

## Authentication — TODO

Currently the `/mcp` endpoint has NO authentication, anyone with the
URL can call it. This is fine for local testing but must be fixed
before anything beyond `ping` touches real backend/AI resources.

Two options going in the connector's "Advanced settings":
- Request header auth (API key/bearer token), simplest, one shared
  credential for now
- OAuth, needed if we want per-user access control later

See: https://claude.com/docs/connectors/custom/remote-mcp

## Tools

- `ping` — test tool, returns a static string, no auth/data access
