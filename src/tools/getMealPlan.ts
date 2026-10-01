import { z } from 'zod';
import { McpError } from '../errors.ts';
import { TOOL_SCOPES } from '../auth/scopes.ts';
import { fetchUpstream } from '../upstream/client.ts';

const MAX_MEALS = 6;
const MAX_RESPONSE_BYTES = 32 * 1024;

const MEAL_TYPES = ['breakfast', 'lunch', 'dinner', 'snack'] as const;

const inputSchema = z
  .object({
    date: z.iso.date().optional(),
    meal_type: z.enum(MEAL_TYPES).optional(),
  })
  .strict();

const MealRowSchema = z
  .object({
    date: z.iso.date().nullable().optional(),

    meal_slot: z.string().min(1).max(50).nullable().optional(),

    meal_type: z.enum(MEAL_TYPES).nullable().optional(),

    recipe_id: z
      .union([z.string().max(200), z.number().int()])
      .nullable()
      .optional(),

    /*
     * Keep this larger than the public output limit so that
     * oversized upstream rows reach the response bounding logic.
     */
    recipe_name: z.string().max(12_000).nullable().optional(),

    energy: z.number().nullable().optional(),

    per_meal_energy: z.number().nullable().optional(),

    energy_kj: z.number().nullable().optional(),
  })
  .strict();

const EntrySchema = z
  .object({
    date: z.iso.date().nullable(),

    meal_slot: z.string().max(50).nullable(),

    recipe_id: z.union([z.string().max(200), z.number().int()]).nullable(),

    recipe_name: z.string().max(6000).nullable(),

    energy: z.number().nullable(),
  })
  .strict();

const OutputSchema = z
  .object({
    date: z.iso.date().nullable(),

    entries: z.array(EntrySchema).max(MAX_MEALS),

    total_available: z.number().int().nonnegative(),

    truncated: z.boolean().optional(),

    more_count: z.number().int().nonnegative().optional(),

    truncation_note: z.string().max(500).optional(),
  })
  .strict();

const contract = {
  title: 'Get Meal Plan',
  description:
    "Get the authenticated user's meal plan. Identity comes only from the exchanged upstream credential.",
  outputSchema: OutputSchema,
} as const;

interface ToolRequest {
  readonly nutrihelpApiBaseUrl: string;
  readonly remainingBudgetMs: () => number;
  readonly correlationId: string;
  readonly credential:
    | {
        readonly accessToken: string;
      }
    | undefined;
}

type MealRow = z.infer<typeof MealRowSchema>;
type MealEntry = z.infer<typeof EntrySchema>;
type MealPlanOutput = z.infer<typeof OutputSchema>;

function upstreamFailure(
  request: ToolRequest,
  errorCode: string,
  startedAt: number,
  status?: number
): McpError {
  let statusClass: 'unreachable' | '5xx' | '4xx' | '2xx';

  if (status === undefined) {
    statusClass = 'unreachable';
  } else if (status >= 500) {
    statusClass = '5xx';
  } else if (status >= 400) {
    statusClass = '4xx';
  } else {
    statusClass = '2xx';
  }

  return new McpError({
    class: 'upstream_failure',
    statusClass,
    errorCode,
    endpointClass: 'meal-plan',
    correlationId: request.correlationId,
    latencyMs: Math.max(0, Date.now() - startedAt),
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function extractMealRows(body: unknown): unknown[] {
  if (!isRecord(body) || !isRecord(body.data) || !Array.isArray(body.data.items)) {
    throw new Error('invalid meal-plan response');
  }

  return body.data.items;
}

function parseMealRows(rows: unknown[]): MealRow[] {
  return rows.flatMap((row) => {
    const parsed = MealRowSchema.safeParse(row);

    return parsed.success ? [parsed.data] : [];
  });
}

function getRecipeName(row: MealRow): string | null {
  const name = row.recipe_name ?? null;

  if (name === null) {
    return null;
  }

  return name.slice(0, 6000);
}

function getMealSlot(row: MealRow): string | null {
  return row.meal_slot ?? row.meal_type ?? null;
}

function getEnergy(row: MealRow): number | null {
  if (row.energy !== null && row.energy !== undefined) {
    return row.energy;
  }

  if (row.per_meal_energy !== null && row.per_meal_energy !== undefined) {
    return row.per_meal_energy;
  }

  if (row.energy_kj !== null && row.energy_kj !== undefined) {
    return row.energy_kj;
  }

  return null;
}

function projectMeal(row: MealRow): MealEntry {
  return {
    date: row.date ?? null,
    meal_slot: getMealSlot(row),
    recipe_id: row.recipe_id ?? null,
    recipe_name: getRecipeName(row),
    energy: getEnergy(row),
  };
}

function buildOutput(rows: MealRow[], requestedDate: string | undefined): MealPlanOutput {
  const totalAvailable = rows.length;

  const entries = rows.slice(0, MAX_MEALS).map(projectMeal);

  const moreCount = Math.max(0, totalAvailable - entries.length);

  const baseOutput = {
    date: requestedDate ?? rows[0]?.date ?? null,
    entries,
    total_available: totalAvailable,
  };

  if (moreCount === 0) {
    return OutputSchema.parse(baseOutput);
  }

  return OutputSchema.parse({
    ...baseOutput,
    truncated: true,
    more_count: moreCount,
    truncation_note: `Showing ${String(entries.length)} of ${String(totalAvailable)} meal entries.`,
  });
}

function serializedSize(output: MealPlanOutput): number {
  return Buffer.byteLength(JSON.stringify(output), 'utf8');
}

function createBoundedOutput(
  output: MealPlanOutput,
  entries: MealEntry[],
  note: string
): MealPlanOutput {
  const moreCount = Math.max(0, output.total_available - entries.length);

  return OutputSchema.parse({
    ...output,
    entries,
    truncated: true,
    more_count: moreCount,
    truncation_note: note,
  });
}

function boundOutput(output: MealPlanOutput): MealPlanOutput {
  const note = 'Response exceeded the 32 KiB limit; additional meal entries were omitted.';

  let entries = [...output.entries];

  while (
    entries.length > 1 &&
    serializedSize(createBoundedOutput(output, entries, note)) > MAX_RESPONSE_BYTES
  ) {
    entries = entries.slice(0, -1);
  }

  return createBoundedOutput(output, entries, note);
}

async function requestMealPlan(
  request: ToolRequest,
  args: z.infer<typeof inputSchema>,
  startedAt: number
): Promise<Response> {
  try {
    return await fetchUpstream({
      baseUrl: request.nutrihelpApiBaseUrl,
      path: '/api/mealplan/',
      declaredParameters: ['date', 'meal_type'],
      toolArguments: args,
      credential: request.credential?.accessToken ?? '',
      deadlineMs: request.remainingBudgetMs(),
      correlationId: request.correlationId,
    });
  } catch (cause: unknown) {
    if (cause instanceof McpError) {
      throw cause;
    }

    throw upstreamFailure(request, 'meal_plan_request_failed', startedAt);
  }
}

async function readMealPlanBody(
  response: Response,
  request: ToolRequest,
  startedAt: number
): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    throw upstreamFailure(request, 'meal_plan_response_invalid', startedAt);
  }
}

export const handler = (request: ToolRequest) => async (args: z.infer<typeof inputSchema>) => {
  const startedAt = Date.now();

  if (request.credential === undefined) {
    throw upstreamFailure(request, 'backend_credential_unavailable', startedAt);
  }

  const response = await requestMealPlan(request, args, startedAt);

  if (!response.ok) {
    await response.body?.cancel();

    throw upstreamFailure(request, 'meal_plan_request_failed', startedAt, response.status);
  }

  const body = await readMealPlanBody(response, request, startedAt);

  let rows: MealRow[];

  try {
    rows = parseMealRows(extractMealRows(body));
  } catch {
    throw upstreamFailure(request, 'meal_plan_response_invalid', startedAt);
  }

  const output = buildOutput(rows, args.date);

  const finalOutput = serializedSize(output) > MAX_RESPONSE_BYTES ? boundOutput(output) : output;

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(finalOutput, null, 2),
      },
    ],
    structuredContent: finalOutput,
  };
};

export const descriptor = {
  name: 'get_meal_plan',
  contract,
  inputSchema,
  scope: TOOL_SCOPES.get_meal_plan,
  backing: 'credentialed',
  handler,
} as const;
