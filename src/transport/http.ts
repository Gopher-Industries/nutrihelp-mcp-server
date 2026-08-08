import express, { type Express } from 'express';
import { createMcpHandler, type McpServerFactory } from '@modelcontextprotocol/server';
import { originValidation, toNodeHandler } from '@modelcontextprotocol/node';

export interface TransportOptions {
  /** Produces a fresh server instance per request. The core is stateless. */
  readonly factory: McpServerFactory;
  readonly allowedOriginHostnames: readonly string[];
  /** Reporting only; never alters the response. */
  readonly onError?: (error: Error) => void;
}

export function createHttpApp(options: TransportOptions): Express {
  const app = express();
  app.disable('x-powered-by');

  const handler = createMcpHandler(options.factory, {
    // Selects 2026-07-28 exclusively; the default serves 2025-era traffic.
    legacy: 'reject',
    ...(options.onError === undefined ? {} : { onerror: options.onError }),
  });

  // The adapter answers its own 500 on conversion or fetch failure and the
  // promise resolves, so this is the only way those surface.
  const mcpHandler = toNodeHandler(handler, {
    ...(options.onError === undefined ? {} : { onerror: options.onError }),
  });
  const validateOrigin = originValidation([...options.allowedOriginHostnames]);

  app.all('/mcp', (req, res) => {
    if (!validateOrigin(req, res)) {
      return;
    }
    void mcpHandler(req, res).catch((cause: unknown) => {
      options.onError?.(cause instanceof Error ? cause : new Error(String(cause)));
      // A rejection here would otherwise be an unhandled rejection, which
      // terminates the process. Close the response without a body.
      if (!res.headersSent) {
        res.status(500).end();
      }
    });
  });

  return app;
}
