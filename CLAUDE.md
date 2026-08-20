# NutriHelp MCP Server

## Environment Variables

The service refuses to start when any required variable is missing or blank.

| Variable | Description |
| --- | --- |
| `PORT` | HTTP listening port. |
| `MCP_ALLOWED_ORIGINS` | Comma-separated browser origin allowlist. |
| `NUTRIHELP_API_BASE_URL` | HTTPS origin for the NutriHelp backend API. |
| `MCP_JWKS_URL` | HTTPS URL of the authorization server JWKS. |
| `MCP_EXPECTED_ISSUER` | Expected HTTPS token issuer. |
| `MCP_RESOURCE_IDENTIFIER` | HTTPS MCP resource identifier, including its path. |
| `MCP_JWKS_CACHE_TTL_S` | JWKS cache lifetime in seconds. |
| `MCP_REQUEST_DEADLINE_MS` | End-to-end MCP request deadline in milliseconds. |
