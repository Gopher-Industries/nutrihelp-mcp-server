import { createHash, randomBytes } from 'node:crypto';
import { McpError, ConfirmationError } from '../errors.ts';
export { ConfirmationError } from '../errors.ts';

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

const MAX_DEPTH = 32;
const MAX_VALUES = 4096;

/** JSON object key order is immaterial; array order, types, and string bytes are preserved. */
export function canonicalJson(value: unknown, maxBytes = 16_384): string {
  let remaining = MAX_VALUES;

  function encode(item: unknown, depth: number): string {
    if (depth > MAX_DEPTH || --remaining < 0) throw new TypeError('Confirmation JSON is too large');
    if (item === null) return 'null';
    if (typeof item !== 'object') return encodeScalar(item, maxBytes);
    if (Array.isArray(item)) return encodeArray(item, depth);
    return encodeObject(item, depth);
  }

  function encodeArray(items: unknown[], depth: number): string {
    if (Reflect.ownKeys(items).length !== items.length + 1) {
      throw new TypeError('Confirmation arguments must be JSON');
    }
    return (
      '[' +
      Array.from({ length: items.length }, (_, i) =>
        encode(dataProperty(items, String(i)), depth + 1)
      ).join(',') +
      ']'
    );
  }

  function encodeObject(item: object, depth: number): string {
    const prototype: unknown = Object.getPrototypeOf(item);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('Confirmation arguments must be JSON');
    }
    const keys = Reflect.ownKeys(item);
    if (keys.some((key) => typeof key !== 'string')) {
      throw new TypeError('Confirmation arguments must be JSON');
    }
    return (
      '{' +
      (keys as string[])
        .sort()
        .map((key) => JSON.stringify(key) + ':' + encode(dataProperty(item, key), depth + 1))
        .join(',') +
      '}'
    );
  }

  const encoded = encode(value, 0);
  if (Buffer.byteLength(encoded, 'utf8') > maxBytes) {
    throw new TypeError('Confirmation JSON is too large');
  }
  return encoded;
}

function dataProperty(item: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(item, key);
  if (descriptor?.enumerable !== true || !('value' in descriptor)) {
    throw new TypeError('Confirmation arguments must be JSON');
  }
  return descriptor.value as unknown;
}

function encodeScalar(item: unknown, maxBytes: number): string {
  if (typeof item === 'boolean') return JSON.stringify(item);
  if (typeof item === 'string' && Buffer.byteLength(item, 'utf8') <= maxBytes) {
    return JSON.stringify(item);
  }
  if (typeof item === 'number' && Number.isFinite(item)) return JSON.stringify(item);
  throw new TypeError('Confirmation arguments must be finite JSON values');
}

export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

// One Redis key per confirmation. TIME and state transitions run together on the server.
const NOW = `
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
`;

export const ISSUE_CONFIRMATION =
  NOW +
  `
local expires = now + tonumber(ARGV[3])
local record = cjson.encode({
  binding_hash = ARGV[1], arguments_hash = ARGV[2],
  state = 'pending', expires_at = expires
})
local inserted = redis.call('SET', KEYS[1], record, 'NX', 'PX', ARGV[3])
if not inserted then return {'collision'} end
return {'issued', tostring(expires)}
`;

export const CLAIM_CONFIRMATION =
  NOW +
  `
local raw = redis.call('GET', KEYS[1])
if not raw then return {'invalid'} end
local record = cjson.decode(raw)
if record.binding_hash ~= ARGV[1] or record.arguments_hash ~= ARGV[2] then
  return {'mismatch'}
end
if record.state == 'done' then return {'done', record.result} end
if record.state == 'in_progress' and record.lease_until > now then
  return {'in_progress', tostring(record.lease_until - now)}
end
if record.expires_at <= now then return {'invalid'} end
if record.state ~= 'pending' and record.state ~= 'in_progress' then return {'invalid'} end
record.state = 'in_progress'
record.owner = ARGV[3]
record.lease_until = now + tonumber(ARGV[4])
redis.call('SET', KEYS[1], cjson.encode(record), 'PX',
  math.max(record.expires_at - now, tonumber(ARGV[5])))
return {'claimed'}
`;

export const COMPLETE_CONFIRMATION = `
local raw = redis.call('GET', KEYS[1])
if not raw then return {'lost'} end
local record = cjson.decode(raw)
if record.binding_hash ~= ARGV[1] or record.arguments_hash ~= ARGV[2]
  or record.state ~= 'in_progress' or record.owner ~= ARGV[3] then
  return {'lost'}
end
record.state = 'done'
record.result = ARGV[4]
record.owner = nil
record.lease_until = nil
redis.call('SET', KEYS[1], cjson.encode(record), 'PX', ARGV[5])
return {'completed'}
`;

/** The composition root supplies the command port; this module owns no connection. */
export interface ConfirmationStorage {
  readonly eval: (
    script: string,
    keys: string[],
    args: string[],
    timeoutMs: number
  ) => Promise<unknown>;
}

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
  storage: ConfirmationStorage,
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
