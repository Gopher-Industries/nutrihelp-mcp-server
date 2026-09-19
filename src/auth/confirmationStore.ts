import { randomBytes } from 'node:crypto';
import { McpError, ConfirmationError } from '../errors.ts';
export { ConfirmationError } from '../errors.ts';
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
  /** Remaining end-to-end request budget from the trusted caller, not model arguments. */
  readonly requestDeadlineMs: number;
}

export interface ConfirmedWrite {
  /** An independent snapshot of exactly the arguments whose hash was checked. */
  readonly arguments: Readonly<Record<string, JsonValue>>;
  /** Ticket 47: forward unchanged as Idempotency-Key. Never send the raw confirmation value. */
  readonly idempotencyKeyHash: string;
  /** Remaining budget after Redis claim; the writer must enforce it on outbound calls. */
  readonly deadlineMs: number;
}

export interface ConfirmationStoredResult {
  readonly id: string;
  readonly status?: string;
}

export type ConfirmationResult =
  | {
      readonly state: 'done';
      readonly result: ConfirmationStoredResult;
      readonly replayed: boolean;
    }
  | { readonly state: 'in_progress'; readonly retryAfterMs: number };

export interface ConfirmationStoreOptions {
  readonly lifetimeMs?: number;
  readonly leaseMs?: number;
  readonly resultTtlMs?: number;
  readonly commandTimeoutMs?: number;
}

const KEY_PREFIX = 'mcp:confirmation:v1:';

function duration(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw invalidInput('confirmation_options', 'positive_bounded_duration');
  }
  return value;
}

function invalidInput(field: string, constraint: string): McpError {
  return new McpError({ class: 'invalid_input', field, constraint });
}

function snapshot(action: ConfirmationAction) {
  try {
    return readSnapshot(action);
  } catch {
    throw invalidInput('confirmation_action', 'valid_binding_and_json_arguments');
  }
}

function readSnapshot(action: ConfirmationAction) {
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
    throw invalidInput('resultTtlMs', 'must_cover_confirmation_lifetime');

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
    const startedAt = performance.now();
    const bound = snapshot(request);
    const requestDeadlineMs = duration(request.requestDeadlineMs, leaseMs - 1);
    if (typeof write !== 'function') throw invalidInput('writer', 'function_required');
    if (
      typeof request.confirmationToken !== 'string' ||
      !/^[A-Za-z0-9_-]{43}$/.test(request.confirmationToken)
    ) {
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
    const deadlineMs = Math.floor(requestDeadlineMs - (performance.now() - startedAt));
    if (deadlineMs <= 0) throw new ConfirmationError('confirmation_write_failed');
    const result = await runWriter(write, {
      arguments: JSON.parse(bound.json) as Record<string, JsonValue>,
      idempotencyKeyHash,
      deadlineMs,
    });
    const projected = projectResult(result);
    const resultJson = canonicalJson(projected, 2_048);
    const completed = await evaluate(COMPLETE_CONFIRMATION, key, [
      ...binding,
      owner,
      resultJson,
      String(resultTtlMs),
    ]);
    if (completed[0] !== 'completed') throw new ConfirmationError('confirmation_attempt_lost');
    return { state: 'done', result: projected, replayed: false };
  }

  return { issue, execute };
}

function readClaimResult(reply: string[]): ConfirmationResult {
  if (reply[0] === 'mismatch') throw new ConfirmationError('confirmation_mismatch');
  if (reply[0] === 'invalid') throw new ConfirmationError('invalid_confirmation');
  if (
    reply[0] === 'in_progress' &&
    Number.isSafeInteger(Number(reply[1])) &&
    Number(reply[1]) > 0
  ) {
    return { state: 'in_progress', retryAfterMs: Number(reply[1]) };
  }
  if (reply[0] === 'done' && reply[1] !== undefined) {
    return readCompletedResult(reply[1]);
  }
  throw new ConfirmationError('confirmation_store_unavailable');
}

function readCompletedResult(json: string): ConfirmationResult {
  try {
    const result: unknown = JSON.parse(json);
    return { state: 'done', result: projectResult(result), replayed: true };
  } catch {
    throw new ConfirmationError('confirmation_store_unavailable');
  }
}

/** Allowlist applies on both completion and replay, including records written by older code. */
function projectResult(value: unknown): ConfirmationStoredResult {
  try {
    assertResultObject(value);
    const id: unknown = Object.getOwnPropertyDescriptor(value, 'id')?.value;
    if (typeof id !== 'string' || id.length === 0 || id.length > 256) throw new Error();
    const status = projectedStatus(value);
    return { id, ...status };
  } catch {
    throw new ConfirmationError('confirmation_result_invalid');
  }
}

function assertResultObject(value: unknown): asserts value is object {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error();
}

function projectedStatus(value: object): { status?: string } {
  const descriptor = Object.getOwnPropertyDescriptor(value, 'status');
  if (descriptor === undefined) return {};
  const status: unknown = descriptor.value;
  if (typeof status !== 'string' || status.length === 0 || status.length > 64) throw new Error();
  return { status };
}

async function runWriter(
  write: (input: ConfirmedWrite) => Promise<JsonValue>,
  input: ConfirmedWrite
): Promise<JsonValue> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      write(input),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new ConfirmationError('confirmation_write_failed'));
        }, input.deadlineMs);
      }),
    ]);
  } catch (error) {
    if (error instanceof McpError) throw error;
    throw new ConfirmationError('confirmation_write_failed');
  } finally {
    clearTimeout(timer);
  }
}

export type ConfirmationStore = ReturnType<typeof createConfirmationStore>;

/** Ticket 49's composition hook. url is trusted Render Key Value configuration, not model input. */
export async function connectConfirmationStore(
  url: string,
  options: ConfirmationStoreOptions = {}
) {
  let connection: KeyValueConnection;
  try {
    connection = await connectKeyValue(url, options.commandTimeoutMs ?? 1_000);
  } catch {
    throw new ConfirmationError('confirmation_store_unavailable');
  }
  try {
    return { ...createConfirmationStore(connection, options), close: connection.close };
  } catch (error) {
    connection.close();
    throw error;
  }
}
