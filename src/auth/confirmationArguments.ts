import { createHash } from 'node:crypto';

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
