import { z } from 'zod';
import { TOOL_SCOPES } from '../auth/scopes.ts';
import { getWithCredential } from '../upstream/client.ts';

const MAX_MEALS = 6;
const MAX_RESPONSE_BYTES = 32 * 1024;

interface ToolRequest {
  readonly nutrihelpApiBaseUrl: string;
  readonly remainingBudgetMs: () => number;
  readonly correlationId: string;
  readonly credential: { readonly accessToken: string } | undefined;
}

const inputSchema = z.object({
  date: z.iso.date().optional(),
  meal_type: z.string().optional(),
});

const outputSchema = z.object({
  meals: z.array(
    z.object({
      date: z.unknown(),
      meal_slot: z.unknown(),
      recipe_id: z.unknown(),
      recipe_name: z.unknown(),
      energy: z.unknown(),
    })
  ),
});

const contract = {
  title: 'Get Meal Plan',
  description:
    "Get the authenticated user's meal plan. The user is identified only by the access token.",
  outputSchema,
};

function formatMealPlan(rows: unknown[]) {
  return rows.slice(0, MAX_MEALS).map((row) => {
    const meal = row as Record<string, unknown>;

    return {
      date: meal.date,
      meal_slot: meal.meal_slot ?? meal.meal_type,
      recipe_id: meal.recipe_id,
      recipe_name: meal.recipe_name,
      energy: meal.energy ?? meal.per_meal_energy,
    };
  });
}

function extractMealRows(body: unknown): unknown[] {
  if (Array.isArray(body)) {
    return body;
  }

  if (body && typeof body === 'object') {
    const data = (body as Record<string, unknown>).data;

    if (Array.isArray(data)) {
      return data;
    }
  }

  return [];
}

export const handler = (request: ToolRequest) => async (args: z.infer<typeof inputSchema>) => {
  if (request.credential === undefined) {
    throw new Error('Meal plan requires an upstream credential');
  }

  const url = new URL('/api/mealplan/me', request.nutrihelpApiBaseUrl);

  if (args.date !== undefined) {
    url.searchParams.set('date', args.date);
  }

  if (args.meal_type !== undefined) {
    url.searchParams.set('meal_type', args.meal_type);
  }

  const response = await getWithCredential({
    url,
    accessToken: request.credential.accessToken,
    deadlineMs: request.remainingBudgetMs(),
    correlationId: request.correlationId,
    redirect: 'error',
  });

  if (!response.ok) {
    throw new Error(`Meal plan request failed with status ${String(response.status)}`);
  }

  const body: unknown = await response.json();
  const rows = extractMealRows(body);

  const output = {
    meals: formatMealPlan(rows),
  };

  if (Buffer.byteLength(JSON.stringify(output), 'utf8') > MAX_RESPONSE_BYTES) {
    throw new Error('Meal plan response exceeded the maximum response size');
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(output, null, 2),
      },
    ],
    structuredContent: output,
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
