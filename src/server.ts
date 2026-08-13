/** Composition root. Wiring only, no logic. */

import 'dotenv/config';

import { McpServer } from '@modelcontextprotocol/server';
import { loadConfig } from './config/index.ts';
import { createHttpApp } from './transport/http.ts';
import { registerTools } from './tools/registry.ts';

const config = loadConfig();

const app = createHttpApp({
  factory: (ctx) => {
    const server = new McpServer({
      name: 'nutrihelp-mcp-server',
      version: '1.0.0',
    });

    registerTools(server, ctx, config);

    return server;
  },
  allowedOriginHostnames: config.allowedOriginHostnames,
  onError: (error: Error) => {
    // TODO(logging): pino.
    console.error(JSON.stringify({ level: 'error', msg: error.message }));
  },
});
app.listen(config.port, () => {
  console.log(JSON.stringify({ level: 'info', msg: 'listening', port: config.port }));
});
