import { z } from 'zod';
import { ConfirmationError, McpError } from '../errors.ts';
import type {
  ConfirmedWrite,
  ConfirmationAction,
  ConfirmationStore,
} from '../consent/confirmation.ts';
import { TOOL_SCOPES } from '../auth/scopes.ts';
import { postCredentialedJson } from '../upstream/client.ts';
/** Structural port: tools do not import the registry or another tool. */
interface ToolRequest {
  readonly nutrihelpApiBaseUrl: string;
  readonly remainingBudgetMs: () => number;
  readonly correlationId: string;
  readonly credential: { readonly accessToken: string } | undefined;
  readonly confirmations: ConfirmationStore;
  readonly caller: {
    readonly subject: string;
    readonly clientId: string;
    readonly grantId: string;
  };
}

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
  date: date.describe('User-supplied meal date in YYYY-MM-DD format; do not infer a date.'),
  meal_type: z
    .string()
    .min(1)
    .max(50)
    .regex(/\S/)
    .describe('User-supplied meal type, for example breakfast.'),
  food_name: z
    .string()
    .min(1)
    .max(200)
    .regex(/\S/)
    .describe('Exact food name supplied by the user.'),
  calories: nutrient
    .optional()
    .describe('Supplied calories, or null/omitted if unknown; never estimate.'),
  protein: nutrient
    .optional()
    .describe('Supplied protein value; leave unknown values null or omitted.'),
  carbs: nutrient.optional().describe('Supplied carbohydrate value; do not estimate.'),
  fat: nutrient.optional().describe('Supplied fat value; do not estimate.'),
  fiber: nutrient.optional().describe('Supplied fiber value; do not estimate.'),
  sugar: nutrient.optional().describe('Supplied sugar value; do not estimate.'),
  sodium: nutrient.optional().describe('Supplied sodium value; do not estimate.'),
  time: time
    .optional()
    .describe('Supplied meal time in HH:MM or HH:MM:SS format; null/omitted if unknown.'),
});

export const inputSchema = mealInputSchema.extend({
  confirmation_token: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/)
    .optional()
    .describe(
      'Omit to preview; repeat the returned token only after the user confirms these exact meal arguments.'
    ),
});

/** Validate the backend record before retaining only the minimal confirmation receipt. */
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
  id: savedMealSchema.shape.id,
});

export const recordMealOutputSchema = z.union([
  z.object({
    class: z.literal('confirmation_required'),
    status: z.literal('confirmation_required'),
    message: z.string(),
    summary: z.string(),
    confirmation_token: z.string(),
  }),
  recordedMealSchema,
  z.object({
    status: z.literal('in_progress'),
    retry_after_ms: z.number().positive(),
    message: z.string(),
  }),
]);

export type MealSnapshot = z.infer<typeof mealInputSchema>;

const backendResponse = z.object({ success: z.literal(true), data: savedMealSchema });
export const MEAL_FIELDS = Object.freeze(Object.keys(mealInputSchema.shape));

function unavailable(request: ToolRequest, errorCode: string): McpError {
  return new McpError({
    class: 'upstream_failure',
    statusClass: 'unavailable',
    errorCode,
    endpointClass: 'meal_log',
    correlationId: request.correlationId,
    latencyMs: 0,
  });
}

function checkStatus(status: number, request: ToolRequest): void {
  if (status === 200 || status === 201) return;
  if (status === 409) throw new ConfirmationError('confirmation_mismatch');
  if (status === 400)
    throw new McpError({
      class: 'invalid_input',
      field: 'arguments',
      constraint: 'Review the meal snapshot before confirming again.',
    });
  // Backend credentials and roles are this server's responsibility, not a login or scope challenge.
  throw unavailable(
    request,
    status === 401 || status === 403 ? 'backend_credential_rejected' : 'backend_write_failed'
  );
}

async function saveMeal(input: ConfirmedWrite, request: ToolRequest) {
  if (request.credential === undefined)
    throw unavailable(request, 'backend_credential_unavailable');
  const response = await postCredentialedJson({
    baseUrl: request.nutrihelpApiBaseUrl,
    path: '/api/meallog/me',
    declaredFields: MEAL_FIELDS,
    body: mealInputSchema.parse(input.arguments),
    credential: request.credential.accessToken,
    idempotencyKeyHash: input.idempotencyKeyHash,
    correlationId: request.correlationId,
    deadlineMs: Math.min(input.deadlineMs, request.remainingBudgetMs()),
  });
  checkStatus(response.status, request);
  const parsed = backendResponse.safeParse(response.body);
  if (!parsed.success) throw unavailable(request, 'backend_response_invalid');
  return { id: parsed.data.data.id, status: 'recorded' as const };
}

async function pending(
  request: ToolRequest,
  action: ConfirmationAction,
  detailCode?: string
): Promise<never> {
  request.remainingBudgetMs();
  const proposal = await request.confirmations.issue(action);
  throw new McpError({
    class: 'confirmation_required',
    summary:
      'Review this exact meal and ask the user to confirm: ' +
      JSON.stringify(action.arguments) +
      '. Omitted nutrition and time are saved as null; nutrition is not estimated.',
    confirmation_token: proposal.confirmationToken,
    ...(detailCode === undefined ? {} : { detailCode }),
  });
}

export const handler = (request: ToolRequest) => async (args: unknown) => {
  const parsed = inputSchema.safeParse(args);
  if (!parsed.success)
    throw new McpError({
      class: 'invalid_input',
      field: 'arguments',
      constraint: 'Match the declared meal schema.',
    });
  const { confirmation_token: confirmationToken, ...meal } = parsed.data;
  const action: ConfirmationAction = {
    binding: {
      userId: request.caller.subject,
      assistantId: request.caller.clientId,
      connectionId: request.caller.grantId,
      tool: 'record_meal',
    },
    arguments: meal,
  };
  if (confirmationToken === undefined) return pending(request, action);
  let saved;
  try {
    saved = await request.confirmations.execute(
      { ...action, confirmationToken, requestDeadlineMs: request.remainingBudgetMs() },
      (input) => saveMeal(input, request)
    );
  } catch (error) {
    if (
      error instanceof ConfirmationError &&
      (error.code === 'invalid_confirmation' || error.code === 'confirmation_mismatch')
    ) {
      return pending(request, action, error.code);
    }
    throw error;
  }
  const output =
    saved.state === 'in_progress'
      ? {
          status: 'in_progress' as const,
          retry_after_ms: saved.retryAfterMs,
          message: 'Retry with the same confirmation token and meal arguments.',
        }
      : recordedMealSchema.parse(saved.result);
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(output) }],
    structuredContent: output,
  };
};

export const contract = {
  title: 'Record Meal',
  description:
    'Preview a meal without confirmation_token. Ask the user to confirm, then repeat the exact meal with the returned token. Never infer nutrition. Retry uncertain writes with the same token.',
  outputSchema: recordMealOutputSchema,
  annotations: {
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: false,
  },
} as const;

export const descriptor = {
  name: 'record_meal',
  contract,
  inputSchema,
  handler,
  scope: TOOL_SCOPES.record_meal,
  backing: 'credentialed',
} as const;
