/**
 * The single dispatch path for every tool.
 */

import type { McpServer, McpRequestContext } from '@modelcontextprotocol/server';

import { descriptor as nutritionLookup } from './nutritionLookup.ts';
import { descriptor as getMealPlan } from './getMealPlan.ts';

export interface RegistryConfig {
  readonly nutrihelpApiBaseUrl: string;
  readonly requestDeadlineMs: number;
}

export function registerTools(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig
): void {
  // Public tools
  const publicTools = [
    {
      ...nutritionLookup,
    },
  ];

  for (const tool of publicTools) {
    server.registerTool(
      tool.name,
      {
        ...tool.contract,
        inputSchema: tool.inputSchema,
      },
      tool.handler(config)
    );
  }

  // Authenticated tools
  if (ctx.authInfo !== undefined) {
    const privateTools = [
      {
        ...getMealPlan,
      },
    ];

    for (const tool of privateTools) {
      server.registerTool(
        tool.name,
        {
          ...tool.contract,
          inputSchema: tool.inputSchema,
        },
        tool.handler(config, ctx.authInfo.token)
      );
    }
  }
}
