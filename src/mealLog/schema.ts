import { z } from 'zod';

/** Ticket 47's snapshot contract. No identity, inferred nutrition, or default dates. */
const nutrient = z.number().min(0).max(Number.MAX_SAFE_INTEGER).nullable();
const date = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((value) => {
    const parsed = new Date(`${value}T00:00:00Z`);
    return (
      !value.startsWith('0000') &&
      !Number.isNaN(parsed.getTime()) &&
      parsed.toISOString().slice(0, 10) === value
    );
  });
const time = z
  .string()
  .regex(/^(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?$/)
  .nullable();

export const mealInputSchema = z.strictObject({
  date,
  meal_type: z.string().min(1).max(50).regex(/\S/),
  food_name: z.string().min(1).max(200).regex(/\S/),
  calories: nutrient.optional(),
  protein: nutrient.optional(),
  carbs: nutrient.optional(),
  fat: nutrient.optional(),
  fiber: nutrient.optional(),
  sugar: nutrient.optional(),
  sodium: nutrient.optional(),
  time: time.optional(),
});

export const recordMealInputSchema = mealInputSchema.extend({
  confirmation_token: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .optional(),
});

/** Allowlist: discard backend-only fields before caching or returning a saved record. */
export const savedMealSchema = z.object({
  id: z
    .string()
    .regex(/^[1-9][0-9]{0,18}$/)
    .refine((value) => /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 9223372036854775807n),
  ...mealInputSchema.shape,
  calories: nutrient,
  protein: nutrient,
  carbs: nutrient,
  fat: nutrient,
  fiber: nutrient,
  sugar: nutrient,
  sodium: nutrient,
  time,
});

export const recordedMealSchema = z.object({
  status: z.literal('recorded'),
  record: savedMealSchema,
});

export const recordMealOutputSchema = z.union([
  z.object({
    class: z.literal('confirmation_required'),
    status: z.literal('confirmation_required'),
    summary: z.string(),
    meal: mealInputSchema,
    confirmation_token: z.string(),
    expires_at: z.number(),
  }),
  recordedMealSchema,
  z.object({
    status: z.literal('in_progress'),
    retry_after_ms: z.number().positive(),
    message: z.string(),
  }),
]);

export type MealSnapshot = z.infer<typeof mealInputSchema>;
