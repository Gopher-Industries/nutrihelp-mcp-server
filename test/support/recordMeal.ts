import { vi } from 'vitest';
import {
  createWriteAuthInfo,
  writeContextFor,
  type WriteContext,
} from '../../src/auth/writeContext.ts';
import { type RecordMealServices } from '../../src/mealLog/runtime.ts';
import { type ConfirmationStore } from '../../src/auth/confirmationStore.ts';
import { NUTRIHELP_API_BASE_URL, RESOURCE_METADATA_URL, SCOPES } from './testEnv.ts';

export const meal = {
  date: '2026-09-18',
  food_name: 'Porridge',
  meal_type: 'breakfast',
  calories: 200,
};
export const storedMeal = {
  id: '9007199254740993',
  ...meal,
  protein: null,
  carbs: null,
  fat: null,
  fiber: null,
  sugar: null,
  sodium: null,
  time: null,
};
export const activeGrant = {
  subject: '7',
  clientId: 'assistant-a',
  grantId: 'connection-a',
  scopes: [SCOPES.meallogWrite],
};
export const mealConfig = { nutrihelpApiBaseUrl: NUTRIHELP_API_BASE_URL, requestDeadlineMs: 30000 };
export const confirmationToken = 'a'.repeat(43);

export function verifiedContext(overrides: Partial<WriteContext> = {}): WriteContext {
  const auth = createWriteAuthInfo(
    {
      sub: activeGrant.subject,
      client_id: activeGrant.clientId,
      grant_id: activeGrant.grantId,
      scope: SCOPES.meallogWrite,
      exp: Date.now() / 1000 + 300,
    },
    activeGrant,
    {
      token: 'inbound-mcp-token',
      correlationId: 'correlation-test',
      deadlineAt: Date.now() + 30000,
      now: Date.now,
      resourceMetadataUrl: RESOURCE_METADATA_URL,
    }
  );
  const context = writeContextFor(auth);
  if (!context) throw new Error('Fixture must create a verified write context');
  return { ...context, ...overrides };
}

export function servicesFor<T extends ConfirmationStore>(confirmations: T) {
  return {
    confirmations,
    revocation: {
      assertGrantActive: vi
        .fn<RecordMealServices['revocation']['assertGrantActive']>()
        .mockResolvedValue(activeGrant),
    },
    exchangeCredential: vi
      .fn<RecordMealServices['exchangeCredential']>()
      .mockResolvedValue('exchanged-backend-token'),
    auditStarted: vi.fn<RecordMealServices['auditStarted']>().mockResolvedValue(undefined),
  } satisfies RecordMealServices;
}
