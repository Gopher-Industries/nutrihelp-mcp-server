/**
 * Local-only dev server for manual/visual testing against real AI clients
 * (LM Studio, Ollama, etc.) that don't yet send the full 2026-07-28 envelope.
 *
 * Deliberately standalone — does not import src/transport/http.ts, so
 * production transport code is never touched by this file. Always
 * permissive. Never deploy this.
 */
import 'dotenv/config';
import express from 'express';
import { McpServer, createMcpHandler, type McpServerFactory } from '@modelcontextprotocol/server';
import { originValidation, toNodeHandler } from '@modelcontextprotocol/node';
import { registerTools } from '../src/tools/registry.ts';

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (value === undefined || value === '') {
    throw new Error(`Missing demo environment variable: ${name}`);
  }
  return value;
}

const port = Number.parseInt(process.env.PORT ?? '3002', 10);
const apiBaseUrl = required('NUTRIHELP_API_BASE_URL');
const apiUrl = new URL(apiBaseUrl);
if (apiUrl.protocol !== 'http:' && apiUrl.protocol !== 'https:') {
  throw new Error('NUTRIHELP_API_BASE_URL must use http or https');
}

const allowedOriginHostnames = required('MCP_ALLOWED_ORIGINS')
  .split(',')
  .map((origin) => new URL(origin.trim()).hostname)
  .filter((hostname, index, hostnames) => hostnames.indexOf(hostname) === index);

const config = { nutrihelpApiBaseUrl: apiBaseUrl };
const app = express();
app.disable('x-powered-by');

const factory: McpServerFactory = (ctx) => {
  const server = new McpServer({ name: 'nutrihelp-mcp-server-dev', version: '1.0.0' });
  registerTools(server, ctx, config);
  return server;
};

const handler = createMcpHandler(factory, { legacy: 'stateless' });
const mcpHandler = toNodeHandler(handler);
const validateOrigin = originValidation(allowedOriginHostnames);

app.all('/mcp', (req, res) => {
  if (!validateOrigin(req, res)) return;
  void mcpHandler(req, res);
});
app.listen(port, () => {
  console.log(`[DEV ONLY] Permissive MCP server on port ${String(port)} — do not deploy this`);
});