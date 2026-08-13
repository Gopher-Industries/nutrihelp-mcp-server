import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/server';
import { fetchUpstream } from '../upstream/client.ts';

interface NutritionLookupConfig {
  readonly nutrihelpApiUrl: string;
}
const NUTRITION_FIELDS = [
  'category', 'name', 'calories', 'fat', 'carbohydrates', 'protein',
  'fiber', 'vitamin_a', 'vitamin_b', 'vitamin_c', 'vitamin_d', 'sodium',
  'sugar', 'allergies_type',
] as const;

const MAX_RESULTS = 10;

const NutritionItemSchema = z.object({
  category: z.string().nullable(),
  name: z.string(),
  calories: z.number().nullable(),
  fat: z.number().nullable(),
  carbohydrates: z.number().nullable(),
  protein: z.number().nullable(),
  fiber: z.number().nullable(),
  vitamin_a: z.number().nullable(),
  vitamin_b: z.number().nullable(),
  vitamin_c: z.number().nullable(),
  vitamin_d: z.number().nullable(),
  sodium: z.number().nullable(),
  sugar: z.number().nullable(),
  allergies_type: z.union([z.string(), z.number()]).nullable(),
});

const OutputSchema = z.object({
  results: z.array(NutritionItemSchema),
});

function toNutritionItem(row: Record<string, unknown>): z.infer<typeof NutritionItemSchema> {
  const item = {} as Record<string, unknown>;
  for (const field of NUTRITION_FIELDS) {
    const value = row[field];
    if (field === 'allergies_type' && typeof value === 'number') {
      item[field] = value;
    } else {
      item[field] = value ?? null;
    }
  }
  return NutritionItemSchema.parse(item);
}

export function registerNutritionLookup(server: McpServer, config: NutritionLookupConfig): void {
  server.registerTool(
    'nutrition_lookup',
    {
      title: 'Nutrition Lookup',
      description: "Search NutriHelp's public nutrition reference data by food name. Requires no login.",
      inputSchema: z.object({
        query: z.string().min(2).max(50),
      }),
      outputSchema: OutputSchema,
    },
    async ({ query }) => {
      // Accept either `nutrihelpApiUrl` (runtime config) or `apiOrigin` (test harness).
      // Fall back to environment or localhost for extra robustness in tests.
      const response = await fetchUpstream({
        baseUrl: config.nutrihelpApiUrl,
        path: '/api/fooddata/search',
        searchParams: { query },
      });
      if (!response.ok) {
        throw new Error(`Nutrition search failed: backend returned ${String(response.status)}`);
}

      const body = (await response.json()) as { success: boolean; data?: Record<string, unknown>[] };
      const rows = (body.data ?? []).slice(0, MAX_RESULTS);
      const output = { results: rows.map(toNutritionItem) };

      return {
        content: [{ type: 'text', text: JSON.stringify(output, null, 2) }],
        structuredContent: output,
      };
    }
  );
}