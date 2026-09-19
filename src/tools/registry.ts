/**
 * The single dispatch path for every tool. server.ts registers tools by calling
 * registerTools — it never imports a tool module directly.
 *
 * Public nutrition lookup and the verified, scoped record_meal descriptor.
 */
import type { McpServer, McpRequestContext } from '@modelcontextprotocol/server';
// 1. Import the plain descriptor package directly from the tool file
import { descriptor as nutritionLookup } from './nutritionLookup.ts';
import { descriptor as recordMeal } from './recordMeal.ts';
import { MEAL_LOG_WRITE_SCOPE, writeContextFor } from '../auth/writeContext.ts';
import type { RecordMealServices } from '../mealLog/runtime.ts';

export interface RegistryConfig {
  readonly nutrihelpApiBaseUrl: string;
  readonly requestDeadlineMs: number;
}

export function registerTools(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig,
  recordMealServices?: RecordMealServices
): void {
  // 2. Build a declarative list of standard, unauthenticated tools
  const publicTools = [
    {
      ...nutritionLookup,
    },
    // Future public tools can be cleanly added to this array
  ];

  // 3. Enumerate and register them cleanly
  for (const tool of publicTools) {
    server.registerTool(
      tool.name,
      { ...tool.contract, inputSchema: tool.inputSchema },
      tool.handler(config)
    );
  }

  const writeContext = writeContextFor(ctx.authInfo);
  if (
    writeContext?.tokenScopes.includes(MEAL_LOG_WRITE_SCOPE) &&
    writeContext.liveScopes.includes(MEAL_LOG_WRITE_SCOPE)
  ) {
    server.registerTool(
      recordMeal.name,
      {
        ...recordMeal.contract,
        inputSchema: recordMeal.inputSchema,
      },
      recordMeal.handler(config, writeContext, recordMealServices)
    );
  }
}
