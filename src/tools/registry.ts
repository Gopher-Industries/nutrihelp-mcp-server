/**
 * The single dispatch path for every tool. server.ts registers tools by calling
 * registerTools — it never imports a tool module directly.
 *
 * Minimal scaffolding (ticket 25) — registers nutrition_lookup unconditionally, since it
 * needs no login. Auth-gated tools land here once they exist, gated on ctx.authInfo.
 */
import type { McpServer, McpRequestContext } from '@modelcontextprotocol/server';
import { registerNutritionLookup } from './nutritionLookup.ts';

export interface RegistryConfig {
  readonly nutrihelpApiUrl: string;
}

export function registerTools(
  server: McpServer,
  ctx: McpRequestContext,
  config: RegistryConfig
): void {
  registerNutritionLookup(server, config);

  // Auth-gated tools land here once they exist, e.g.:
  // if (ctx.authInfo) { registerGetMealPlan(server, config); }
}
