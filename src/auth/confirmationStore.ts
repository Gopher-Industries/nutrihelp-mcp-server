import { randomBytes } from 'node:crypto';
import { connectKeyValue, type KeyValueConnection } from '../upstream/client.ts';
import { canonicalJson, sha256, type JsonValue } from './confirmationArguments.ts';
import {
  ISSUE_CONFIRMATION,
  CLAIM_CONFIRMATION,
  COMPLETE_CONFIRMATION,
} from './confirmationScripts.ts';

export interface ConfirmationBinding {
  /** All identity fields come from verified auth / live grant data, never tool arguments. */
  readonly userId: string;
  readonly assistantId: string;
  readonly connectionId: string;
  readonly tool: string;
}

export interface ConfirmationAction {
  readonly binding: ConfirmationBinding;
  /** Validated write arguments only; exclude the confirmation_token control field. */
  readonly arguments: Readonly<Record<string, unknown>>;
}

export interface ConfirmationRequest extends ConfirmationAction {
  readonly confirmationToken: string;
}

export interface ConfirmedWrite {
  /** An independent snapshot of exactly the arguments whose hash was checked. */
  readonly arguments: Readonly<Record<string, JsonValue>>;
  /** Ticket 47: forward unchanged as Idempotency-Key. Never send the raw confirmation value. */
  readonly idempotencyKeyHash: string;
}

export type ConfirmationResult =
  | { readonly state: 'done'; readonly result: JsonValue; readonly replayed: boolean }
  | { readonly state: 'in_progress'; readonly retryAfterMs: number };

export interface ConfirmationStoreOptions {
  readonly lifetimeMs?: number;
  readonly leaseMs?: number;
  readonly resultTtlMs?: number;
  readonly commandTimeoutMs?: number;
}

export class ConfirmationError extends Error {
  readonly code:
    | 'invalid_confirmation'
    | 'confirmation_store_unavailable'
    | 'confirmation_attempt_lost';
  constructor(
    code: 'invalid_confirmation' | 'confirmation_store_unavailable' | 'confirmation_attempt_lost'
  ) {
    super(
      code === 'invalid_confirmation'
        ? 'This confirmation is invalid or expired.'
        : 'The confirmation could not be completed. Retry with the same confirmation.'
    );
    this.name = 'ConfirmationError';
    this.code = code;
  }
}

const KEY_PREFIX = 'mcp:confirmation:v1:';

function duration(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new TypeError('Invalid confirmation duration');
  }
  return value;
}

function snapshot(action: ConfirmationAction) {
  const identity = [
    action.binding.userId,
    action.binding.assistantId,
    action.binding.connectionId,
    action.binding.tool,
  ];
  if (
    identity.some((value) => typeof value !== 'string' || value.trim() === '' || value.length > 512)
  ) {
    throw new TypeError('A complete verified confirmation binding is required');
  }
  const argumentsValue: unknown = action.arguments;
  if (
    typeof argumentsValue !== 'object' ||
    argumentsValue === null ||
    Array.isArray(argumentsValue)
  ) {
    throw new TypeError('Confirmation arguments must be an object');
  }
  const json = canonicalJson(action.arguments);
  return { bindingHash: sha256(canonicalJson(identity)), argumentsHash: sha256(json), json };
}

/** Redis-backed only: there is no process-local fallback when recording fails. */
export function createConfirmationStore(
  storage: Pick<KeyValueConnection, 'eval'>,
  options: ConfirmationStoreOptions = {}
) {
  const lifetimeMs = duration(options.lifetimeMs ?? 300_000, 900_000);
  const leaseMs = duration(options.leaseMs ?? 30_000, lifetimeMs);
  const resultTtlMs = duration(options.resultTtlMs ?? 86_400_000, 86_400_000);
  const commandTimeoutMs = duration(options.commandTimeoutMs ?? 1_000, 60_000);
  if (resultTtlMs < lifetimeMs)
    throw new TypeError('Result retention must cover the confirmation lifetime');

  async function evaluate(script: string, key: string, args: string[]): Promise<string[]> {
    try {
      const result = await storage.eval(script, [key], args, commandTimeoutMs);
      if (!Array.isArray(result) || !result.every((part: unknown) => typeof part === 'string')) {
        throw new Error('Invalid store reply');
      }
      return result;
    } catch {
      // Redis errors may carry credentials or command arguments. Do not preserve their cause.
      throw new ConfirmationError('confirmation_store_unavailable');
    }
  }

  async function issue(action: ConfirmationAction) {
    const bound = snapshot(action);
    const confirmationToken = randomBytes(32).toString('base64url');
    const reply = await evaluate(ISSUE_CONFIRMATION, KEY_PREFIX + sha256(confirmationToken), [
      bound.bindingHash,
      bound.argumentsHash,
      String(lifetimeMs),
    ]);
    const expiresAt = Number(reply[1]);
    if (reply[0] !== 'issued' || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
      throw new ConfirmationError('confirmation_store_unavailable');
    }
    return { confirmationToken, expiresAt };
  }

  async function execute(
    request: ConfirmationRequest,
    write: (input: ConfirmedWrite) => Promise<JsonValue>
  ): Promise<ConfirmationResult> {
    const bound = snapshot(request);
    if (!/^[A-Za-z0-9_-]{43}$/.test(request.confirmationToken)) {
      throw new ConfirmationError('invalid_confirmation');
    }
    const idempotencyKeyHash = sha256(request.confirmationToken);
    const key = KEY_PREFIX + idempotencyKeyHash;
    const owner = randomBytes(16).toString('hex');
    const binding = [bound.bindingHash, bound.argumentsHash];
    const reply = await evaluate(CLAIM_CONFIRMATION, key, [
      ...binding,
      owner,
      String(leaseMs),
      String(resultTtlMs),
    ]);
    if (reply[0] !== 'claimed') return readClaimResult(reply);

    // A timeout may follow a committed write. Keep in_progress: the next lease uses the SAME key.
    // Ticket 49 must recheck live grant + scope before execute(), including cached-result reads.
    const result = await write({
      arguments: JSON.parse(bound.json) as Record<string, JsonValue>,
      idempotencyKeyHash,
    });
    const resultJson = canonicalJson(result, 65_536);
    const completed = await evaluate(COMPLETE_CONFIRMATION, key, [
      ...binding,
      owner,
      resultJson,
      String(resultTtlMs),
    ]);
    if (completed[0] !== 'completed') throw new ConfirmationError('confirmation_attempt_lost');
    return { state: 'done', result: JSON.parse(resultJson) as JsonValue, replayed: false };
  }

  return { issue, execute };
}

function readClaimResult(reply: string[]): ConfirmationResult {
  if (reply[0] === 'invalid') throw new ConfirmationError('invalid_confirmation');
  if (
    reply[0] === 'in_progress' &&
    Number.isSafeInteger(Number(reply[1])) &&
    Number(reply[1]) > 0
  ) {
    return { state: 'in_progress', retryAfterMs: Number(reply[1]) };
  }
  if (reply[0] === 'done' && reply[1] !== undefined) {
    try {
      const result: unknown = JSON.parse(reply[1]);
      return {
        state: 'done',
        result: JSON.parse(canonicalJson(result, 65_536)) as JsonValue,
        replayed: true,
      };
    } catch {
      throw new ConfirmationError('confirmation_store_unavailable');
    }
  }
  throw new ConfirmationError('confirmation_store_unavailable');
}

export type ConfirmationStore = ReturnType<typeof createConfirmationStore>;

/** Ticket 49's composition hook. url is trusted Render Key Value configuration, not model input. */
export async function connectConfirmationStore(
  url: string,
  options: ConfirmationStoreOptions = {}
) {
  const connection = await connectKeyValue(url, options.commandTimeoutMs ?? 1_000);
  try {
    return { ...createConfirmationStore(connection, options), close: connection.close };
  } catch (error) {
    connection.close();
    throw error;
  }
}
