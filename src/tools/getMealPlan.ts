import { z } from 'zod';
import { getWithCredential } from '../upstream/client.ts';

const MAX_MEALS = 6;
const MAX_RESPONSE_BYTES = 32 * 1024;

export interface GetMealPlanConfig {
  readonly nutrihelpApiBaseUrl: string;
  readonly requestDeadlineMs: number;
}

const inputSchema = z.object({
  date: z.iso.date().optional(),
  meal_type: z.string().optional(),
});

const contract = {
  description:
    "Get the authenticated user's meal plan. The user is identified only by the access token.",
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

export const handler =
  (config: GetMealPlanConfig, accessToken: string) => async (args: z.infer<typeof inputSchema>) => {
    const url = new URL('/api/mealplan/me', config.nutrihelpApiBaseUrl);

    if (args.date !== undefined) {
      url.searchParams.set('date', args.date);
    }

    if (args.meal_type !== undefined) {
      url.searchParams.set('meal_type', args.meal_type);
    }

    const response = await getWithCredential({
      url,
      accessToken,
      deadlineMs: config.requestDeadlineMs,
      correlationId: undefined,
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
  handler,
} as const;
