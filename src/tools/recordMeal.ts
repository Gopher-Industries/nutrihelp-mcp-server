import { z } from 'zod';
import { ConfirmationError, type ConfirmedWrite } from '../auth/confirmationStore.ts';
import {
  assertMealWriteAuthorized,
  MEAL_LOG_WRITE_SCOPE,
  remainingWriteBudget,
  writeUnavailable,
  type WriteContext,
} from '../auth/writeContext.ts';
import { McpError } from '../errors.ts';
import {
  mealInputSchema,
  recordMealInputSchema,
  recordedMealSchema,
  recordMealOutputSchema,
  savedMealSchema,
  type MealSnapshot,
} from '../mealLog/schema.ts';
import type { RecordMealConfig, RecordMealServices } from '../mealLog/runtime.ts';
import { postMealLog } from '../upstream/client.ts';
import { frameToolResult } from '../transport/toolResult.ts';

const backendResponse = z.object({ success: z.literal(true), data: savedMealSchema });

function result(value: z.infer<typeof recordMealOutputSchema>) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(value) }],
    structuredContent: value,
  };
}

function assertBackendSuccess(status: number, context: WriteContext): void {
  if (status === 200 || status === 201) return;
  if (status === 409) throw new ConfirmationError('confirmation_mismatch');
  if (status === 400)
    throw new McpError({
      class: 'invalid_input',
      field: 'arguments',
      constraint:
        'The backend refused the meal snapshot. Review the meal before requesting a new confirmation.',
    });
  if (status === 401)
    throw new McpError({
      class: 'unauthorized',
      reason: 'backend_credential_rejected',
      resourceMetadataUrl: context.resourceMetadataUrl,
    });
  if (status === 403)
    throw new McpError({
      class: 'insufficient_scope',
      requiredScope: MEAL_LOG_WRITE_SCOPE,
      heldScopes: context.tokenScopes,
      resourceMetadataUrl: context.resourceMetadataUrl,
      userId: context.userId,
      clientId: context.assistantId,
      grantId: context.connectionId,
      operation: 'record_meal',
    });
  throw writeUnavailable(context, 'backend_write_failed');
}

async function saveMeal(
  input: ConfirmedWrite,
  context: WriteContext,
  services: RecordMealServices,
  config: RecordMealConfig
) {
  // The store subtracts Redis claim time. Preserve that smaller budget through exchange,
  // live authorization and the HTTP write; each async step consumes the same deadline.
  const startedAt = context.now();
  const monotonicStart = performance.now();
  const writeContext: WriteContext = {
    ...context,
    deadlineAt: Math.min(context.deadlineAt, startedAt + input.deadlineMs),
    now: () => Math.max(context.now(), startedAt + (performance.now() - monotonicStart)),
  };
  const meal = mealInputSchema.parse(input.arguments);
  const credential = await services.exchangeCredential({
    subjectToken: context.token,
    scope: MEAL_LOG_WRITE_SCOPE,
    correlationId: context.correlationId,
    deadlineMs: remainingWriteBudget(writeContext),
  });
  if (!credential || credential === context.token)
    throw writeUnavailable(context, 'backend_credential_unavailable');
  // Exchange may take time. Recheck immediately before the write, after every async precondition.
  await assertMealWriteAuthorized(writeContext, services.revocation);
  const response = await postMealLog({
    baseUrl: config.nutrihelpApiBaseUrl,
    meal,
    credential,
    idempotencyKeyHash: input.idempotencyKeyHash,
    correlationId: context.correlationId,
    deadlineMs: remainingWriteBudget(writeContext),
  });
  assertBackendSuccess(response.status, context);
  const parsed = backendResponse.safeParse(await response.json());
  if (!parsed.success) throw writeUnavailable(context, 'backend_response_invalid');
  return { id: parsed.data.data.id, status: 'recorded' as const };
}

async function run(
  args: unknown,
  context: WriteContext,
  services: RecordMealServices,
  config: RecordMealConfig
) {
  const parsed = recordMealInputSchema.safeParse(args);
  if (!parsed.success)
    throw new McpError({
      class: 'invalid_input',
      field: 'arguments',
      constraint: 'Match the declared meal schema.',
    });
  const { confirmation_token: confirmationToken, ...meal } = parsed.data;
  await assertMealWriteAuthorized(context, services.revocation);
  await services.auditStarted({
    userId: context.userId,
    assistantId: context.assistantId,
    connectionId: context.connectionId,
    tool: 'record_meal',
    phase: confirmationToken === undefined ? 'proposal' : 'confirmation',
    correlationId: context.correlationId,
    deadlineMs: remainingWriteBudget(context),
  });
  // Audit can also take time; no cached result escapes after a disconnect during that wait.
  await assertMealWriteAuthorized(context, services.revocation);
  const action = {
    binding: {
      userId: context.userId,
      assistantId: context.assistantId,
      connectionId: context.connectionId,
      tool: 'record_meal',
    },
    arguments: meal,
  };
  if (confirmationToken === undefined) {
    const proposal = await services.confirmations.issue(action);
    return result({
      class: 'confirmation_required',
      status: 'confirmation_required',
      summary: summarize(meal),
      meal,
      confirmation_token: proposal.confirmationToken,
      expires_at: proposal.expiresAt,
    });
  }
  const saved = await services.confirmations.execute(
    { ...action, confirmationToken, requestDeadlineMs: remainingWriteBudget(context) },
    (input) => saveMeal(input, context, services, config)
  );
  if (saved.state === 'in_progress')
    return result({
      status: 'in_progress',
      retry_after_ms: saved.retryAfterMs,
      message:
        'This confirmation is being processed. Retry with the same token and meal arguments.',
    });
  // Cache contents are also untrusted upstream data; apply the public allowlist again.
  return result(recordedMealSchema.parse(saved.result));
}

function summarize(meal: MealSnapshot): string {
  return `Save ${JSON.stringify(meal.food_name)} as ${JSON.stringify(meal.meal_type)} on ${meal.date}? Review the meal fields and ask the user to confirm. Omitted nutrition and time are saved as null; nutrition is not estimated.`;
}

export function handler(
  config: RecordMealConfig,
  context: WriteContext,
  services: RecordMealServices | undefined
) {
  return (args: unknown) =>
    frameToolResult(async () => {
      if (services === undefined) throw writeUnavailable(context, 'record_meal_not_configured');
      return run(args, context, services, config);
    });
}

export const descriptor = {
  name: 'record_meal',
  inputSchema: recordMealInputSchema,
  contract: {
    title: 'Record Meal',
    description:
      'Record a meal snapshot for the connected user. First call without confirmation_token to preview the exact fields. Ask the user to confirm, then repeat the identical arguments with the returned confirmation_token. Never infer nutrition or create a new confirmation to retry an uncertain write.',
    outputSchema: recordMealOutputSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  handler,
} as const;
