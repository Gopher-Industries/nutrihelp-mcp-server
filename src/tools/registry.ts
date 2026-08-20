/**
 * The single dispatch path for every tool. server.ts registers tools by calling
 * registerTools — it never imports a tool module directly.
 *
 * Minimal scaffolding (ticket 25) — registers nutrition_lookup. Auth-gated tools land here once they exist, gated on ctx.authInfo.
 */
import type { McpServer, McpRequestContext } from '@modelcontextprotocol/server';
// 1. Import the plain descriptor package directly from the tool file
import * as nutritionLookup from './nutritionLookup.ts';

export interface RegistryConfig {
  readonly nutrihelpApiBaseUrl: string;
}

export function registerTools(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig
): void {
  // 2. Build a declarative list of standard, unauthenticated tools
  const publicTools = [
    {
      name: 'nutrition_lookup',
      descriptor: nutritionLookup,
    },
    // Future public tools can be cleanly added to this array
  ];

  // 3. Enumerate and register them cleanly
  for (const tool of publicTools) {
    server.registerTool(
      tool.name,
      {
        ...tool.descriptor.contract,
        inputSchema: tool.descriptor.inputSchema,
      },
      tool.descriptor.handler(config)
    );
  }

  // 4. Auth-gated tools land here declaratively once they exist, e.g.:
  // if (ctx.authInfo) {
  //   const privateTools = [ ... ];
  //   // loop and register private tools
  // }
}
