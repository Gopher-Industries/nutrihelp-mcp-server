import { vi } from 'vitest';
import type { CallToolResult, McpServer } from '@modelcontextprotocol/server';
import {
  registerTools,
  type ConfirmationAnomalyEvent,
  type RegistryConfig,
} from '../../src/tools/registry.ts';
import { sha256, type ConfirmationStore } from '../../src/consent/confirmation.ts';
import type { RequestAuthorization } from '../../src/transport/http.ts';
import { forgeActiveGrant } from './activeGrant.ts';
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
export const confirmationToken = 'a'.repeat(43);
export const mealConfig = { nutrihelpApiBaseUrl: NUTRIHELP_API_BASE_URL };

export function setupMeal() {
  const confirmations = {
    issue: vi
      .fn<ConfirmationStore['issue']>()
      .mockResolvedValue({ confirmationToken, expiresAt: 1790000000000 }),
    execute: vi.fn<ConfirmationStore['execute']>().mockImplementation(async (request, write) => ({
      state: 'done',
      replayed: false,
      result: (await write({
        arguments: request.arguments as typeof meal,
        idempotencyKeyHash: sha256(request.confirmationToken),
        deadlineMs: request.requestDeadlineMs - 1,
      })) as { id: string; status: string },
    })),
  };
  const anomalies: ConfirmationAnomalyEvent[] = [];
  const credentialFor = vi.fn<RequestAuthorization['credentialFor']>().mockResolvedValue({
    accessToken: 'exchanged-backend-token',
    grantId: 'connection-a',
    usableUntilMs: Date.now() + 60000,
  });
  const authorization: RequestAuthorization = {
    grant: forgeActiveGrant({
      subject: '7',
      clientId: 'assistant-a',
      grantId: 'connection-a',
      scopes: [SCOPES.meallogWrite],
      subjectToken: 'inbound-mcp-token',
    }),
    subjectToken: 'inbound-mcp-token',
    correlationId: 'correlation-test',
    deadlineAt: Date.now() + 30000,
    now: Date.now,
    credentialFor,
  };
  const config: RegistryConfig = {
    ...mealConfig,
    confirmations,
    authorizationFor: () => authorization,
    resourceMetadataUrl: RESOURCE_METADATA_URL,
    auditEnqueue: vi.fn().mockResolvedValue(undefined),
    logSecurity: vi.fn(),
    logOperational: vi.fn(),
    logConfirmationAnomaly: (event) => anomalies.push(event),
  };
  const callbacks = new Map<string, (args: unknown) => Promise<CallToolResult>>();
  const server = {
    registerTool: (
      name: string,
      _contract: unknown,
      callback: (args: unknown) => Promise<CallToolResult>
    ) => {
      callbacks.set(name, callback);
    },
  } as unknown as McpServer;
  registerTools(
    server,
    { era: 'modern', authInfo: { token: 'digest', clientId: 'untrusted', scopes: [] } },
    config
  );
  const call = (args: unknown) => {
    const callback = callbacks.get('record_meal');
    if (!callback) throw new Error('record_meal is not registered');
    return callback(args);
  };
  return { call, config, confirmations, anomalies, authorization, credentialFor };
}
