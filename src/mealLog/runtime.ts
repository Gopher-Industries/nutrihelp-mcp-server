import type { ConfirmationStore } from '../auth/confirmationStore.ts';
import type { RevocationChecker } from '../auth/revocation.ts';

/** Trusted composition adapters, never tool arguments. No anonymous or in-memory fallback. */
export interface RecordMealServices {
  readonly confirmations: ConfirmationStore;
  readonly revocation: RevocationChecker;
  /** Ticket 29/31: return the exchanged backend credential, never the inbound MCP token. */
  readonly exchangeCredential: (request: {
    readonly subjectToken: string;
    readonly scope: 'meallog:write';
    readonly correlationId: string;
    readonly deadlineMs: number;
  }) => Promise<string>;
  /** Ticket 34: resolves only after `started` is durable (ingest or shared buffer). */
  readonly auditStarted: (event: {
    readonly userId: string;
    readonly assistantId: string;
    readonly connectionId: string;
    readonly tool: 'record_meal';
    readonly phase: 'proposal' | 'confirmation';
    readonly correlationId: string;
    readonly deadlineMs: number;
  }) => Promise<void>;
}

export interface RecordMealConfig {
  readonly nutrihelpApiBaseUrl: string;
}
