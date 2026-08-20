import { z } from 'zod';
import { fetchUpstream } from '../upstream/client.ts';
import { RetryableUpstreamError } from '../errors.ts';

const NUTRITION_FIELDS = [
  'category',
  'name',
  'calories',
  'fat',
  'carbohydrates',
  'protein',
  'fiber',
  'vitamin_a',
  'vitamin_b',
  'vitamin_c',
  'vitamin_d',
  'sodium',
  'sugar',
  'allergies_type',
  'serving_size',
] as const;
const MAX_CANDIDATES = 5;
const MAX_RESPONSE_BYTES = 32 * 1024;

export const inputSchema = z.object({
  food: z.string().min(2).max(50),
  id: z.number().int().positive().optional(),
  quantity: z.number().positive().optional(),
  unit: z.string().min(1).max(20).optional(),
});

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
  serving_size: z.string().nullable(),
});

const CandidateSchema = z.object({ id: z.number(), name: z.string() });

const OutputSchema = z.object({
  results: z.array(NutritionItemSchema),
  candidates: z.array(CandidateSchema).max(MAX_CANDIDATES).optional(),
  total_available: z.number().int().nonnegative(),
  truncated: z.boolean(),
  truncation_note: z.string().optional(),
});

function toNutritionItem(row: Record<string, unknown>): z.infer<typeof NutritionItemSchema> {
  return NutritionItemSchema.parse(
    Object.fromEntries(NUTRITION_FIELDS.map((field) => [field, row[field] ?? null]))
  );
}

export const contract = {
  title: 'Nutrition Lookup',
  description:
    'Search NutriHelp nutrition data. Auth is not wired yet - blocked on tickets 27/59/34. This tool requires nutrition:read and live introspection like every other tool.',
  outputSchema: OutputSchema,
} as const;

interface NutritionLookupConfig {
  readonly nutrihelpApiBaseUrl: string;
}

// Extracted Helper: Fetches and parses raw upstream data safely
async function fetchNutritionData(
  config: NutritionLookupConfig,
  food: string
): Promise<Record<string, unknown>[]> {
  try {
    const response = await fetchUpstream({
      baseUrl: config.nutrihelpApiBaseUrl,
      path: '/api/fooddata/search',
      searchParams: { query: food },
    });
    if (!response.ok) throw new RetryableUpstreamError();

    const body = await response.json();
    const parsed = z
      .object({ data: z.array(z.record(z.string(), z.unknown())).default([]) })
      .safeParse(body);

    if (!parsed.success) throw new RetryableUpstreamError();
    return parsed.data.data;
  } catch {
    throw new RetryableUpstreamError();
  }
}

// Extracted Helper: Builds the output schema object based on search results
function formatOutput(rows: Record<string, unknown>[], targetId?: number) {
  const totalAvailable = rows.length;
  const selected =
    targetId !== undefined
      ? rows.find((row) => row.id === targetId)
      : totalAvailable === 1
        ? rows[0]
        : undefined;

  if (selected !== undefined) {
    return {
      results: [toNutritionItem(selected)],
      total_available: totalAvailable,
      truncated: false,
    };
  }

  const candidates = rows
    .filter(
      (row): row is typeof row & { id: number; name: string } =>
        typeof row.id === 'number' && typeof row.name === 'string'
    )
    .map((row) => ({ id: row.id, name: row.name }))
    .slice(0, MAX_CANDIDATES);

  return {
    results: [],
    candidates,
    total_available: totalAvailable,
    truncated: totalAvailable > MAX_CANDIDATES,
    truncation_note:
      'Multiple matches found. Call again with the same food text and the id of the one you want.',
  };
}

// Main tool handler function (Complexity drops from 9 to 2)
export const handler =
  (config: NutritionLookupConfig) => async (args: z.infer<typeof inputSchema>) => {
    const rows = await fetchNutritionData(config, args.food);
    const output = formatOutput(rows, args.id);

    if (Buffer.byteLength(JSON.stringify(output), 'utf8') > MAX_RESPONSE_BYTES) {
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({
              results: [],
              total_available: rows.length,
              truncated: true,
              truncation_note: 'Response exceeded the 32 KiB limit; refine the food search.',
            }),
          },
        ],
      };
    }

    return {
      content: [{ type: 'text' as const, text: JSON.stringify(output, null, 2) }],
      structuredContent: output,
    };
  };
