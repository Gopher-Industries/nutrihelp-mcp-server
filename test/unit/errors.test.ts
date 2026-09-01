/**
 * Taxonomy suite, written from the plan. Assertions match constructor *values*, not payload
 * key names, except the construction-surface block, which is a proposal (the plan does not fix
 * the constructor signature).
 *
 * Presence uses `carriesExactly` (no prefix/suffix matches). Absence uses `textIncludes` (loose
 * is stronger). `LOG_ONLY_SENTINELS` pins declared log-side fields so a model leak of a legitimate
 * slot cannot pass as "no extras".
 */

import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  MCP_ERROR_CLASSES,
  McpError,
  PROTOCOL_ERROR_CODES,
  type McpErrorClass,
} from '../../src/errors.ts';

/* Hand-written class pin, not derived from the module. Exact count so delete or add both go red. */

const EXPECTED_CLASSES = [
  'unauthorized',
  'insufficient_scope',
  'invalid_input',
  'upstream_failure',
  'confirmation_required',
] as const;

const EXPECTED_CLASS_COUNT = 5;

/* Distinctive sentinels: a match is evidence, not coincidence. */

const SENTINEL = {
  reason: 'REASON-SENTINEL-audience-mismatch-9f13',
  resourceMetadataUrl: 'https://mcp.example.test/.well-known/oauth-protected-resource/mcp',
  requiredScope: 'meals:read',
  heldScope: 'nutrition:read',
  userId: 'USER-SENTINEL-4a71',
  clientId: 'CLIENT-SENTINEL-b2e0',
  grantId: 'GRANT-SENTINEL-77c5',
  operation: 'tools/call:get_meal_plan',
  field: 'servingSize',
  constraint: 'must be a positive integer',
  statusClass: '5xx',
  // Opaque so an absence check cannot false-red on a generic retry message.
  errorCode: 'ERRCODE-SENTINEL-upstream-unavailable-6d2f',
  endpointClass: 'meal-plan',
  correlationId: 'CORRELATION-SENTINEL-1d9c',
  // Implausible so a different numeric field cannot satisfy it by coincidence.
  latencyMs: 604937,
  summary: 'Log 1 bowl of oats to breakfast on 12 March. SUMMARY-SENTINEL-8b02',
  confirmationToken: 'CONFIRMATION-TOKEN-SENTINEL-e604',
  unresolvedItems: ['UNRESOLVED-SENTINEL-quinoa-flakes-5c31', 'UNRESOLVED-SENTINEL-oat-milk-b17f'],
} as const;

/** Values the taxonomy has no slot for. Reaching a payload means the init was spread. */
const FORBIDDEN = {
  statusCode: 599,
  internalPath: '/api/internal/mealplan/by-user/42',
  stackFrame: 'at leakyFrame (src/upstream/client.ts:42:13)',
  responseBody: '{"secret":"BODY-SENTINEL-3f8a","rows":[]}',
} as const;

const FORBIDDEN_EXTRAS: Record<string, unknown> = {
  statusCode: FORBIDDEN.statusCode,
  status: FORBIDDEN.statusCode,
  path: FORBIDDEN.internalPath,
  internalPath: FORBIDDEN.internalPath,
  stack: `Error: upstream refused\n    ${FORBIDDEN.stackFrame}`,
  responseBody: FORBIDDEN.responseBody,
  body: FORBIDDEN.responseBody,
  details: FORBIDDEN.responseBody,
};

/* Construction surface — proposed, not pinned. Change these builders if the signature changes. */

type ErrorInit = ConstructorParameters<typeof McpError>[0];

function construct(init: Record<string, unknown>, extra: Record<string, unknown>): McpError {
  return new McpError({ ...init, ...extra } as unknown as ErrorInit);
}

function anUnauthorized(extra: Record<string, unknown> = {}): McpError {
  return construct(
    {
      class: 'unauthorized',
      reason: SENTINEL.reason,
      resourceMetadataUrl: SENTINEL.resourceMetadataUrl,
    },
    extra
  );
}

function anInsufficientScope(extra: Record<string, unknown> = {}): McpError {
  return construct(
    {
      class: 'insufficient_scope',
      requiredScope: SENTINEL.requiredScope,
      heldScopes: [SENTINEL.heldScope],
      resourceMetadataUrl: SENTINEL.resourceMetadataUrl,
      userId: SENTINEL.userId,
      clientId: SENTINEL.clientId,
      grantId: SENTINEL.grantId,
      operation: SENTINEL.operation,
    },
    extra
  );
}

function anInvalidInput(extra: Record<string, unknown> = {}): McpError {
  return construct(
    {
      class: 'invalid_input',
      field: SENTINEL.field,
      constraint: SENTINEL.constraint,
    },
    extra
  );
}

function anUpstreamFailure(extra: Record<string, unknown> = {}): McpError {
  return construct(
    {
      class: 'upstream_failure',
      statusClass: SENTINEL.statusClass,
      errorCode: SENTINEL.errorCode,
      endpointClass: SENTINEL.endpointClass,
      correlationId: SENTINEL.correlationId,
      latencyMs: SENTINEL.latencyMs,
    },
    extra
  );
}

/** `confirmation_token` spelling is pinned (round-trips as the input argument), not proposed. */
function aConfirmationRequired(extra: Record<string, unknown> = {}): McpError {
  return construct(
    {
      class: 'confirmation_required',
      summary: SENTINEL.summary,
      confirmation_token: SENTINEL.confirmationToken,
    },
    extra
  );
}

/** Pending action with unresolved items listed to the model. */
function aConfirmationRequiredWithUnresolvedItems(extra: Record<string, unknown> = {}): McpError {
  return construct(
    {
      class: 'confirmation_required',
      summary: SENTINEL.summary,
      confirmation_token: SENTINEL.confirmationToken,
      unresolved_items: [...SENTINEL.unresolvedItems],
    },
    extra
  );
}

/** Empty list must omit the key, same as absent. */
function aConfirmationRequiredWithEmptyUnresolvedItems(
  extra: Record<string, unknown> = {}
): McpError {
  return construct(
    {
      class: 'confirmation_required',
      summary: SENTINEL.summary,
      confirmation_token: SENTINEL.confirmationToken,
      unresolved_items: [],
    },
    extra
  );
}

/* End of proposed surface. */

interface ClassUnderTest {
  readonly name: McpErrorClass;
  readonly build: (extra?: Record<string, unknown>) => McpError;
}

const CLASSES_UNDER_TEST: readonly ClassUnderTest[] = [
  { name: 'unauthorized', build: anUnauthorized },
  { name: 'insufficient_scope', build: anInsufficientScope },
  { name: 'invalid_input', build: anInvalidInput },
  { name: 'upstream_failure', build: anUpstreamFailure },
  { name: 'confirmation_required', build: aConfirmationRequired },
];

/* Hand-written log-only pin, not derived. Empty rows are the two classes with no log-only fields.
 * `errorCode` is on this list: it sits in the log-column sentence with status class, endpoint
 * class, correlation id and latency. */

type LogOnlyField = readonly [field: string, sentinel: string | number];

const LOG_ONLY_SENTINELS: Readonly<Record<McpErrorClass, readonly LogOnlyField[]>> = {
  unauthorized: [['reason', SENTINEL.reason]],
  insufficient_scope: [
    ['userId', SENTINEL.userId],
    ['clientId', SENTINEL.clientId],
    ['grantId', SENTINEL.grantId],
    ['operation', SENTINEL.operation],
    ['heldScopes', SENTINEL.heldScope],
  ],
  invalid_input: [],
  upstream_failure: [
    ['statusClass', SENTINEL.statusClass],
    ['errorCode', SENTINEL.errorCode],
    ['endpointClass', SENTINEL.endpointClass],
    ['correlationId', SENTINEL.correlationId],
    ['latencyMs', SENTINEL.latencyMs],
  ],
  confirmation_required: [],
};

const EXPECTED_LOG_ONLY_FIELD_COUNT = 11;

const CLASSES_WITH_NO_LOG_ONLY_FIELD = ['invalid_input', 'confirmation_required'] as const;

function allLogOnlyFields(): readonly LogOnlyField[] {
  return Object.values(LOG_ONLY_SENTINELS).flat();
}

/* Shape-agnostic walks: a later field rename cannot falsify a value-based case. */

/** Own property names plus reachable primitives. Includes non-enumerable `stack`. */
function deepStrings(value: unknown, seen = new WeakSet<object>()): string[] {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') return [value];
  if (typeof value === 'symbol') return [value.toString()];
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return [String(value)];
  }
  if (typeof value !== 'object') return [];
  if (seen.has(value)) return [];
  seen.add(value);

  const out: string[] = [];
  const record = value as Record<string, unknown>;
  for (const key of Object.getOwnPropertyNames(value)) {
    out.push(key);
    try {
      out.push(...deepStrings(record[key], seen));
    } catch {
      out.push('<unreadable>');
    }
  }
  return out;
}

/** One string, with a separator no payload can contain, so no match spans two values. */
function payloadText(payload: unknown): string {
  return deepStrings(payload).join('\u0000');
}

/**
 * Exact match on a scalar or on a quoted challenge parameter. A value that merely extends the
 * expected one (`…/mcp/nope`) satisfies neither arm.
 */
function carriesExactly(payload: unknown, value: string | number): boolean {
  const wanted = String(value);
  const strings = deepStrings(payload);
  return strings.includes(wanted) || strings.some((entry) => entry.includes(`"${wanted}"`));
}

/** The loose form. Used for absence, where loose is strictly stronger, and for prose. */
function textIncludes(payload: unknown, needle: string | number): boolean {
  return payloadText(payload).includes(String(needle));
}

/** Values under an own property with this name, at any depth. */
function valuesAtKey(key: string, value: unknown, seen = new WeakSet<object>()): unknown[] {
  if (value === null || typeof value !== 'object') return [];
  if (seen.has(value)) return [];
  seen.add(value);

  const out: unknown[] = [];
  const record = value as Record<string, unknown>;
  for (const name of Object.getOwnPropertyNames(value)) {
    let child: unknown;
    try {
      child = record[name];
    } catch {
      continue;
    }
    if (name === key) out.push(child);
    out.push(...valuesAtKey(key, child, seen));
  }
  return out;
}

/** Whether an own property with this name exists anywhere in the payload, whatever it holds. */
function hasKeyAnywhere(key: string, payload: unknown): boolean {
  return valuesAtKey(key, payload).length > 0;
}

/** `error` property or rendered `error="…"`. The class discriminant alone is not enough. */
function carriesChallengeErrorIdentifier(payload: unknown, identifier: string): boolean {
  const underErrorKey = valuesAtKey('error', payload).includes(identifier);
  const inRenderedChallenge = deepStrings(payload).some((entry) =>
    entry.includes(`error="${identifier}"`)
  );
  return underErrorKey || inRenderedChallenge;
}

/** A payload that is `{}` passes every absence assertion. Every leak group calls this. */
function expectNonEmptyPayload(payload: unknown, label: string): void {
  expect(payload, `${label}: a null payload passes every absence check`).not.toBeNull();
  expect(typeof payload, `${label}: a payload is an object`).toBe('object');
  expect(
    Object.keys(payload as object).length,
    `${label}: an empty payload passes every absence check, so the leak guards would be vacuous`
  ).toBeGreaterThan(0);
}

function expectNoForbiddenMaterial(payload: unknown, label: string): void {
  expectNonEmptyPayload(payload, label);
  expect(textIncludes(payload, FORBIDDEN.statusCode), `${label} carries a status code`).toBe(false);
  expect(textIncludes(payload, FORBIDDEN.internalPath), `${label} carries an internal path`).toBe(
    false
  );
  expect(textIncludes(payload, FORBIDDEN.stackFrame), `${label} carries a stack frame`).toBe(false);
  expect(textIncludes(payload, FORBIDDEN.responseBody), `${label} carries a response body`).toBe(
    false
  );
}

/* Compile-time exhaustiveness: a sixth union member makes `never` fail typecheck here. */

function nameOf(errorClass: McpErrorClass): string {
  switch (errorClass) {
    case 'unauthorized':
      return 'unauthorized';
    case 'insufficient_scope':
      return 'insufficient_scope';
    case 'invalid_input':
      return 'invalid_input';
    case 'upstream_failure':
      return 'upstream_failure';
    case 'confirmation_required':
      return 'confirmation_required';
    default: {
      const unreachable: never = errorClass;
      return unreachable;
    }
  }
}

/* --- The five classes ------------------------------------------------------------------------ */

describe('the class set', () => {
  it('pins five classes by hand, and the pin itself is not empty', () => {
    expect(
      EXPECTED_CLASSES.length,
      'entries were deleted from the hand-written pin, and each one took its assertions with it'
    ).toBe(EXPECTED_CLASS_COUNT);
    expect(new Set(EXPECTED_CLASSES).size, 'the pin lists a class twice').toBe(
      EXPECTED_CLASS_COUNT
    );
  });

  it('declares exactly those five and no sixth', () => {
    expect(MCP_ERROR_CLASSES.length, 'a class was added or removed without updating the pin').toBe(
      EXPECTED_CLASS_COUNT
    );

    expect([...MCP_ERROR_CLASSES].sort()).toEqual([...EXPECTED_CLASSES].sort());
  });

  it('names each class exactly, with no spelling drift', () => {
    for (const expected of EXPECTED_CLASSES) {
      expect(
        (MCP_ERROR_CLASSES as readonly string[]).includes(expected),
        `"${expected}" is a declared error class`
      ).toBe(true);
    }
  });

  it('switches over the union exhaustively', () => {
    for (const expected of EXPECTED_CLASSES) {
      expect(nameOf(expected)).toBe(expected);
    }
  });

  it('has one builder per class here, so the per-class groups below cover all five', () => {
    expect(CLASSES_UNDER_TEST.length).toBe(EXPECTED_CLASS_COUNT);
    expect(CLASSES_UNDER_TEST.map((entry) => entry.name).sort()).toEqual(
      [...EXPECTED_CLASSES].sort()
    );
  });
});

describe('every class', () => {
  it.each(CLASSES_UNDER_TEST)(
    '$name is an McpError carrying its own discriminant',
    ({ name, build }) => {
      const error = build();

      expect(error).toBeInstanceOf(McpError);
      expect(error).toBeInstanceOf(Error);
      expect(error.class).toBe(name);
    }
  );

  it.each(CLASSES_UNDER_TEST)(
    '$name returns two payloads, not one object twice',
    ({ name, build }) => {
      const error = build();
      const model: unknown = error.toModel();
      const log: unknown = error.toLog();

      expectNonEmptyPayload(model, `${name} toModel()`);
      expectNonEmptyPayload(log, `${name} toLog()`);
      expect(
        model,
        'toModel() and toLog() returned the same object. Reaching the log-side detail has to ' +
          'require a different payload, or the two-column split is decorative'
      ).not.toBe(log);
    }
  );

  it.each(CLASSES_UNDER_TEST)(
    '$name puts undeclared input into neither payload',
    ({ name, build }) => {
      const error = build(FORBIDDEN_EXTRAS);

      expectNoForbiddenMaterial(error.toModel(), `${name} toModel()`);
      expectNoForbiddenMaterial(error.toLog(), `${name} toLog()`);
    }
  );
});

describe('the log-only half of the two columns', () => {
  it('pins the log-only fields by hand, and the pin is neither empty nor self-aliasing', () => {
    expect(
      Object.keys(LOG_ONLY_SENTINELS).sort(),
      'a class was added or removed without deciding which fields are log-only'
    ).toEqual([...EXPECTED_CLASSES].sort());

    expect(
      allLogOnlyFields().length,
      'rows were deleted from the pin; each one took a model-leak guard with it'
    ).toBe(EXPECTED_LOG_ONLY_FIELD_COUNT);

    const empty = Object.entries(LOG_ONLY_SENTINELS)
      .filter(([, fields]) => fields.length === 0)
      .map(([name]) => name)
      .sort();
    expect(
      empty,
      'a class list emptied here stops asserting silently, because iterating no rows passes'
    ).toEqual([...CLASSES_WITH_NO_LOG_ONLY_FIELD].sort());

    const sentinels = allLogOnlyFields().map(([, sentinel]) => String(sentinel));
    expect(
      new Set(sentinels).size,
      'two rows share a sentinel, so one of them is satisfied by the other and proves nothing'
    ).toBe(sentinels.length);
  });

  it.each(
    CLASSES_UNDER_TEST.map((entry) => ({ ...entry, logOnly: LOG_ONLY_SENTINELS[entry.name] }))
  )(
    '$name keeps every declared log-only field out of the model payload',
    ({ name, build, logOnly }) => {
      const error = build();
      const model: unknown = error.toModel();
      const log: unknown = error.toLog();

      expectNonEmptyPayload(model, `${name} toModel()`);
      expectNonEmptyPayload(log, `${name} toLog()`);

      for (const [field, sentinel] of logOnly) {
        expect(
          carriesExactly(log, sentinel),
          `${name}: ${field} is log-side; dropping it would make the absence check below pass vacuously`
        ).toBe(true);
        expect(
          textIncludes(model, sentinel),
          `${name}: ${field} belongs to the log column, not the model payload`
        ).toBe(false);
      }
    }
  );
});

/* Instance surface, not accessors. `{ err }` logging already leaked via payload-on-cause.
 * JSON sees enumerable own props; getOwnPropertyNames sees non-enumerable too. `stack`/`message`
 * must stay non-enumerable. Cases also assert expected content so an empty instance cannot pass. */

const INTRINSIC_ERROR_SLOTS = ['stack', 'message'] as const;

const EXPECTED_ERROR_NAME = 'McpError';

const STRING_FORBIDDEN_VALUES: readonly string[] = [
  FORBIDDEN.internalPath,
  FORBIDDEN.stackFrame,
  FORBIDDEN.responseBody,
];

const ALL_FORBIDDEN_VALUES: readonly (string | number)[] = [
  FORBIDDEN.statusCode,
  ...STRING_FORBIDDEN_VALUES,
];

/** Own properties minus `stack`/`message`, which carry V8 paths that would false-red a numeric sentinel. */
function ownSurfaceWithoutIntrinsics(error: McpError): Record<string, unknown> {
  const surface: Record<string, unknown> = {};
  for (const key of Object.getOwnPropertyNames(error)) {
    if ((INTRINSIC_ERROR_SLOTS as readonly string[]).includes(key)) continue;
    try {
      surface[key] = (error as unknown as Record<string, unknown>)[key];
    } catch {
      surface[key] = '<unreadable>';
    }
  }
  return surface;
}

interface InstanceCase {
  readonly name: McpErrorClass;
  readonly mode: string;
  readonly build: (extra?: Record<string, unknown>) => McpError;
  readonly extra: Record<string, unknown>;
}

/** With and without forbidden extras: both constructions can leak. */
const INSTANCE_CONSTRUCTIONS: readonly {
  readonly mode: string;
  readonly extra: Record<string, unknown>;
}[] = [
  { mode: 'as constructed', extra: {} },
  { mode: 'built with forbidden extras', extra: FORBIDDEN_EXTRAS },
];

const INSTANCE_CASES: readonly InstanceCase[] = CLASSES_UNDER_TEST.flatMap((entry) =>
  INSTANCE_CONSTRUCTIONS.map((construction) => ({
    name: entry.name,
    mode: construction.mode,
    build: entry.build,
    extra: construction.extra,
  }))
);

const EXPECTED_INSTANCE_CASE_COUNT = EXPECTED_CLASS_COUNT * 2;

describe('the error instance itself', () => {
  it('covers every class in both constructions, so the groups below are not a subset', () => {
    expect(
      INSTANCE_CASES.length,
      'a construction or a class was dropped, and every case below got quieter without going red'
    ).toBe(EXPECTED_INSTANCE_CASE_COUNT);

    expect([...new Set(INSTANCE_CASES.map((entry) => entry.name))].sort()).toEqual(
      [...EXPECTED_CLASSES].sort()
    );
    expect([...new Set(INSTANCE_CASES.map((entry) => entry.mode))].length).toBe(
      INSTANCE_CONSTRUCTIONS.length
    );
    expect(
      Object.keys(FORBIDDEN_EXTRAS).length,
      'control: the forbidden-extras construction supplies something, or half this table is a ' +
        'duplicate of the other half'
    ).toBeGreaterThan(0);
  });

  it.each(INSTANCE_CASES)(
    '$name $mode serialises to its class and its name, and to nothing else',
    ({ name, build, extra }) => {
      const error = build(extra);
      const parsed = JSON.parse(JSON.stringify(error)) as Record<string, unknown>;

      // Exact shape: an extra enumerable field is red immediately. Value-by-value absence stays
      // so a later legitimate enumerable field does not retire the sentinel checks.
      expect(
        parsed,
        'enumerable instance fields beyond class/name reach `{ err }` without calling toLog()'
      ).toEqual({ class: name, name: EXPECTED_ERROR_NAME });
    }
  );

  it.each(INSTANCE_CASES)(
    '$name $mode serialises no log-only field and no forbidden material',
    ({ name, build, extra }) => {
      const error = build(extra);
      const serialised = JSON.stringify(error);
      const parsed = JSON.parse(serialised) as Record<string, unknown>;

      expect(
        parsed.class,
        'control: an instance that serialised to nothing would pass every absence check below'
      ).toBe(name);

      for (const [field, sentinel] of allLogOnlyFields()) {
        expect(
          serialised.includes(String(sentinel)),
          `${name}: ${field} is log-only; serialising the instance is not calling toLog()`
        ).toBe(false);
      }

      for (const value of ALL_FORBIDDEN_VALUES) {
        expect(
          serialised.includes(String(value)),
          `${name}: the instance serialises material the taxonomy has no slot for at all`
        ).toBe(false);
      }
    }
  );

  it.each(INSTANCE_CASES)(
    '$name $mode exposes no own property carrying log-only or forbidden material, at any depth',
    ({ name, build, extra }) => {
      const error = build(extra);
      const surface = ownSurfaceWithoutIntrinsics(error);

      expect(
        Object.keys(surface).length,
        'control: an instance with no own properties passes every absence check below'
      ).toBeGreaterThan(0);
      expect(
        surface.class,
        'control: the discriminant is still reachable on the instance, so the walk had a subject'
      ).toBe(name);

      // Names and nested values, so a leak inside an innocuous object is still caught.
      for (const [field, sentinel] of allLogOnlyFields()) {
        expect(
          textIncludes(surface, sentinel),
          `${name}: ${field} is reachable by reflection on the instance. Non-enumerable is not ` +
            'private: a debugger, a snapshot serialiser and getOwnPropertyNames all read it'
        ).toBe(false);
      }

      for (const value of ALL_FORBIDDEN_VALUES) {
        expect(
          textIncludes(surface, value),
          `${name}: undeclared input reached the instance, so the constructor spread what it was ` +
            'given instead of taking the fields the taxonomy declares'
        ).toBe(false);
      }
    }
  );

  it.each(INSTANCE_CASES)(
    '$name $mode keeps the intrinsic stack and message non-enumerable',
    ({ name, build, extra }) => {
      const error = build(extra);

      expect(
        Object.prototype.hasOwnProperty.call(error, 'stack'),
        'control: the slot under test exists, so the enumerability assertion has a subject ' +
          'rather than passing because there is nothing there'
      ).toBe(true);

      for (const slot of INTRINSIC_ERROR_SLOTS) {
        expect(
          Object.prototype.propertyIsEnumerable.call(error, slot),
          `${name}: ${slot} must stay non-enumerable or a serialised stack reaches the model`
        ).toBe(false);
      }

      expect(Object.keys(error), `${name}: stack is enumerable`).not.toContain('stack');
      expect(Object.keys(error), `${name}: message is enumerable`).not.toContain('message');
    }
  );

  it.each(INSTANCE_CASES)(
    '$name $mode keeps log-only and forbidden strings out of its stack and message',
    ({ name, build, extra }) => {
      const error = build(extra);
      const stack = typeof error.stack === 'string' ? error.stack : '';

      expect(stack.length, 'control: there is a stack to check').toBeGreaterThan(0);
      expect(
        error.message.length,
        'control: there is a message to check, so the absence checks below are not over an empty ' +
          'string'
      ).toBeGreaterThan(0);

      const intrinsicText = `${stack}\u0000${error.message}`;

      for (const value of STRING_FORBIDDEN_VALUES) {
        expect(
          intrinsicText.includes(value),
          `${name}: an injected stack, path or body reached the intrinsic Error slots, which are ` +
            'precisely the two fields a logger emits for a bare error'
        ).toBe(false);
      }

      // String sentinels only: a V8 stack is full of line numbers, so a numeric sentinel false-reds.
      const stringSentinels = allLogOnlyFields().filter(
        (entry): entry is readonly [string, string] => typeof entry[1] === 'string'
      );
      expect(
        stringSentinels.length,
        'control: every log-only sentinel became numeric, so the loop below asserts nothing'
      ).toBeGreaterThan(0);

      for (const [field, sentinel] of stringSentinels) {
        expect(
          intrinsicText.includes(sentinel),
          `${name}: ${field} reached stack or message; both are emitted by a standard serialiser`
        ).toBe(false);
      }
    }
  );
});

describe('unauthorized', () => {
  it('points the model at the resource metadata document', () => {
    const model: unknown = anUnauthorized().toModel();

    expect(carriesExactly(model, SENTINEL.resourceMetadataUrl)).toBe(true);
  });

  it('does not tell the model which check failed', () => {
    const model: unknown = anUnauthorized().toModel();

    expectNonEmptyPayload(model, 'unauthorized toModel()');
    expect(
      textIncludes(model, SENTINEL.reason),
      'naming the failed check helps someone probing the verifier, and a legitimate client ' +
        'refreshes either way'
    ).toBe(false);
  });

  it('gives logs the full reason', () => {
    const log: unknown = anUnauthorized().toLog();

    expect(carriesExactly(log, SENTINEL.reason)).toBe(true);
  });
});

describe('insufficient_scope', () => {
  it('names the required scope and the resource metadata document to the model', () => {
    const model: unknown = anInsufficientScope().toModel();

    expect(carriesExactly(model, SENTINEL.requiredScope)).toBe(true);
    expect(carriesExactly(model, SENTINEL.resourceMetadataUrl)).toBe(true);
  });

  it('carries the insufficient_scope error identifier exactly, as the error field', () => {
    const model: unknown = anInsufficientScope().toModel();

    // Discriminant holds the same string; pin the challenge `error` field separately.
    expect(carriesExactly(model, 'insufficient_scope')).toBe(true);
    expect(
      carriesChallengeErrorIdentifier(model, 'insufficient_scope'),
      'challenge must carry error="insufficient_scope" (or an error property); class is not that field'
    ).toBe(true);
  });

  it('gives logs the user, client, grant, operation, held scopes and required scope', () => {
    const log: unknown = anInsufficientScope().toLog();

    expect(carriesExactly(log, SENTINEL.userId)).toBe(true);
    expect(carriesExactly(log, SENTINEL.clientId)).toBe(true);
    expect(carriesExactly(log, SENTINEL.grantId)).toBe(true);
    expect(carriesExactly(log, SENTINEL.operation)).toBe(true);
    expect(carriesExactly(log, SENTINEL.heldScope)).toBe(true);
    expect(carriesExactly(log, SENTINEL.requiredScope)).toBe(true);
  });
});

describe('invalid_input', () => {
  it('names the offending field and the constraint to the model', () => {
    const model: unknown = anInvalidInput().toModel();

    expect(carriesExactly(model, SENTINEL.field)).toBe(true);
    expect(
      carriesExactly(model, SENTINEL.constraint) || textIncludes(model, SENTINEL.constraint),
      'this is the one class that gets more detail, so the model can correct itself'
    ).toBe(true);
  });

  it('is not a protocol error', () => {
    expect(
      Object.keys(PROTOCOL_ERROR_CODES).includes('invalid_input'),
      'a schema failure is a tool execution error, so the model can retry with better arguments'
    ).toBe(false);
  });

  it('gives logs the field and the constraint too', () => {
    const log: unknown = anInvalidInput().toLog();

    expect(carriesExactly(log, SENTINEL.field)).toBe(true);
    expect(carriesExactly(log, SENTINEL.constraint) || textIncludes(log, SENTINEL.constraint)).toBe(
      true
    );
  });
});

describe('upstream_failure', () => {
  it('gives the model no status code, internal path, stack trace or response body', () => {
    const model: unknown = anUpstreamFailure(FORBIDDEN_EXTRAS).toModel();

    expectNoForbiddenMaterial(model, 'upstream_failure toModel()');
    expect(
      deepStrings(model).includes('stack'),
      'a payload with a stack property is a stack trace on its way to a model'
    ).toBe(false);
  });

  it('keeps the status class on the log side only', () => {
    const error = anUpstreamFailure();

    expect(carriesExactly(error.toLog(), SENTINEL.statusClass)).toBe(true);
    expect(
      textIncludes(error.toModel(), SENTINEL.statusClass),
      'the model gets a generic retryable message; a status family is a status code'
    ).toBe(false);
  });

  it('keeps the stable error code on the log side only', () => {
    const error = anUpstreamFailure();

    expect(carriesExactly(error.toLog(), SENTINEL.errorCode)).toBe(true);
    expect(
      textIncludes(error.toModel(), SENTINEL.errorCode),
      'errorCode is log-column; the model gets a generic retryable message'
    ).toBe(false);
  });

  it('gives logs the status class, stable error code, endpoint class, correlation id, latency', () => {
    const log: unknown = anUpstreamFailure().toLog();

    expect(carriesExactly(log, SENTINEL.statusClass)).toBe(true);
    expect(carriesExactly(log, SENTINEL.errorCode)).toBe(true);
    expect(carriesExactly(log, SENTINEL.endpointClass)).toBe(true);
    expect(carriesExactly(log, SENTINEL.correlationId)).toBe(true);
    expect(carriesExactly(log, SENTINEL.latencyMs)).toBe(true);
  });

  it('keeps the response body, details and stack off the log side as well', () => {
    const log: unknown = anUpstreamFailure(FORBIDDEN_EXTRAS).toLog();

    expectNonEmptyPayload(log, 'upstream_failure toLog()');
    expect(textIncludes(log, FORBIDDEN.responseBody)).toBe(false);
    expect(textIncludes(log, FORBIDDEN.stackFrame)).toBe(false);
    expect(deepStrings(log).includes('stack')).toBe(false);
  });

  it('returns two payloads that differ, not one payload rendered twice', () => {
    const error = anUpstreamFailure();
    const model: unknown = error.toModel();
    const log: unknown = error.toLog();

    expect(model).not.toBe(log);
    expect(
      model,
      'the model payload and the log payload carry the same content, so the two-column split ' +
        'is a naming convention rather than a control'
    ).not.toEqual(log);
  });
});

describe('confirmation_required', () => {
  it('returns a structured pending action to the model', () => {
    const model: unknown = aConfirmationRequired().toModel();

    expectNonEmptyPayload(model, 'confirmation_required toModel()');
    expect(carriesExactly(model, SENTINEL.confirmationToken)).toBe(true);
  });

  it('hands the model the confirmation token under that exact field name', () => {
    const model: unknown = aConfirmationRequired().toModel();

    expect(
      valuesAtKey('confirmation_token', model),
      'confirmation_token must round-trip under that exact field name'
    ).toContain(SENTINEL.confirmationToken);
  });

  it('carries a human-readable summary to the model', () => {
    const model: unknown = aConfirmationRequired().toModel();

    expect(
      textIncludes(model, 'SUMMARY-SENTINEL-8b02'),
      'the summary shown to the user is generated server-side, so it has to reach the model'
    ).toBe(true);
  });

  it('lists every unresolved item to the model when the write did not fully resolve', () => {
    const model: unknown = aConfirmationRequiredWithUnresolvedItems().toModel();

    expectNonEmptyPayload(model, 'confirmation_required toModel()');
    for (const item of SENTINEL.unresolvedItems) {
      expect(
        carriesExactly(model, item),
        'an unrecognised item comes back named, so the user confirms a whole meal or none. ' +
          'Dropping one from the list is how a partial meal gets recorded silently'
      ).toBe(true);
    }
    expect(
      valuesAtKey('unresolved_items', model).length,
      'the list has to arrive under its own field name, not folded into the prose summary'
    ).toBeGreaterThan(0);
  });

  it('omits the unresolved-items field entirely when every item resolved', () => {
    const model: unknown = aConfirmationRequired().toModel();

    expectNonEmptyPayload(model, 'confirmation_required toModel()');
    expect(
      hasKeyAnywhere('unresolved_items', model),
      'unresolved_items must be omitted when nothing was unresolved'
    ).toBe(false);
  });

  it('omits the unresolved-items field entirely when the list arrives empty', () => {
    const model: unknown = aConfirmationRequiredWithEmptyUnresolvedItems().toModel();

    expectNonEmptyPayload(model, 'confirmation_required toModel()');
    expect(
      carriesExactly(model, SENTINEL.confirmationToken),
      'control: the rest of the pending action is still here'
    ).toBe(true);
    expect(
      hasKeyAnywhere('unresolved_items', model),
      'empty unresolved_items is the same as absent: omit the key'
    ).toBe(false);
  });

  it('records the pending action on the log side', () => {
    const log: unknown = aConfirmationRequired().toLog();

    expect(carriesExactly(log, SENTINEL.confirmationToken)).toBe(true);
  });
});

/* Protocol codes: JSON-RPC envelope only. `invalid_input` and `confirmation_required` are
 * successful tool results. Pins are hand-written and not derived from each other or from the
 * module. `-32005` is retired. Membership and count, not the live numbers. */

const EXPECTED_PROTOCOL_CODE_CLASSES = [
  'unauthorized',
  'insufficient_scope',
  'upstream_failure',
] as const;

const EXPECTED_PROTOCOL_CODE_COUNT = 3;

/** Tool-result classes: no envelope code. Separate from the log-only empty list — different contract. */
const CLASSES_WITHOUT_PROTOCOL_CODE = ['invalid_input', 'confirmation_required'] as const;

/** Assigned to `confirmation_required` once; never reassign. */
const RETIRED_PROTOCOL_CODE = -32005;

function codeEntries(): readonly (readonly [string, number])[] {
  return Object.entries(PROTOCOL_ERROR_CODES).filter(
    (entry): entry is [string, number] => typeof entry[1] === 'number'
  );
}

describe('protocol error codes', () => {
  it('pins the coded and uncoded classes by hand, and the two pins partition the taxonomy', () => {
    expect(
      EXPECTED_PROTOCOL_CODE_CLASSES.length,
      'entries were deleted from the pin; a shorter list is a quieter suite, not a tighter one'
    ).toBe(EXPECTED_PROTOCOL_CODE_COUNT);
    expect(
      new Set(EXPECTED_PROTOCOL_CODE_CLASSES).size,
      'the pin lists a class twice, so the count is met without covering three classes'
    ).toBe(EXPECTED_PROTOCOL_CODE_COUNT);

    expect(
      CLASSES_WITHOUT_PROTOCOL_CODE.length,
      'control: emptying the uncoded pin would leave the exclusion case below iterating nothing'
    ).toBeGreaterThan(0);

    const overlap = EXPECTED_PROTOCOL_CODE_CLASSES.filter((name) =>
      (CLASSES_WITHOUT_PROTOCOL_CODE as readonly string[]).includes(name)
    );
    expect(overlap, 'a class is pinned as both carrying and not carrying a code').toEqual([]);

    expect(
      [...EXPECTED_PROTOCOL_CODE_CLASSES, ...CLASSES_WITHOUT_PROTOCOL_CODE].sort(),
      'a class was added or removed without deciding envelope vs tool-result'
    ).toEqual([...EXPECTED_CLASSES].sort());
  });

  it('declares exactly the three the pin names, and no fourth', () => {
    expect(
      Object.keys(PROTOCOL_ERROR_CODES).length,
      'a class gained or lost an envelope code without updating the pin'
    ).toBe(EXPECTED_PROTOCOL_CODE_COUNT);

    expect(Object.keys(PROTOCOL_ERROR_CODES).sort()).toEqual(
      [...EXPECTED_PROTOCOL_CODE_CLASSES].sort()
    );
  });

  it('carries a code under each pinned class name, with no spelling drift', () => {
    const keys = Object.keys(PROTOCOL_ERROR_CODES);

    for (const name of EXPECTED_PROTOCOL_CODE_CLASSES) {
      expect(
        keys,
        `"${name}" is reported as a protocol error and needs an envelope code`
      ).toContain(name);
    }
  });

  it('gives no envelope code to a class the server returns to the model as a tool result', () => {
    const keys = Object.keys(PROTOCOL_ERROR_CODES);

    expect(
      keys.length,
      'control: an empty map would satisfy every absence check below without the exclusion ' +
        'meaning anything'
    ).toBeGreaterThan(0);

    for (const name of CLASSES_WITHOUT_PROTOCOL_CODE) {
      expect(
        (EXPECTED_CLASSES as readonly string[]).includes(name),
        `control: "${name}" is a declared class, so its absence from the code map is an exclusion ` +
          'rather than a name the taxonomy never had'
      ).toBe(true);

      expect(keys.includes(name), `"${name}" is a tool result, not a JSON-RPC error envelope`).toBe(
        false
      );
    }
  });

  it('never reassigns the code a review retired', () => {
    for (const [name, code] of codeEntries()) {
      expect(
        code,
        `${name} was given a code a review took away from another class. Reusing it makes a ` +
          'retired assignment indistinguishable from a live one in every log and every client'
      ).not.toBe(RETIRED_PROTOCOL_CODE);
    }
  });

  it('mints at least one, so the range assertions below are not vacuous', () => {
    expect(
      codeEntries().length,
      'an empty map satisfies every "for each code" assertion in this group'
    ).toBeGreaterThan(0);
    expect(
      codeEntries().length,
      'a declared code is not a number, and the range assertions below silently skip it'
    ).toBe(Object.keys(PROTOCOL_ERROR_CODES).length);
    expect(
      codeEntries().length,
      'the loops below iterate the numeric entries, so a map that shrank would quietly assert ' +
        'less while still passing every per-code check'
    ).toBe(EXPECTED_PROTOCOL_CODE_COUNT);
  });

  it('keys the map only by declared error classes', () => {
    for (const [name] of codeEntries()) {
      expect((EXPECTED_CLASSES as readonly string[]).includes(name), name).toBe(true);
    }
  });

  it('stays inside -32000 to -32019', () => {
    for (const [name, code] of codeEntries()) {
      expect(Number.isInteger(code), name).toBe(true);
      expect(code, name).toBeLessThanOrEqual(-32000);
      expect(code, name).toBeGreaterThanOrEqual(-32019);
    }
  });

  it('leaves the reserved -32020 to -32099 band unused', () => {
    for (const [name, code] of codeEntries()) {
      expect(code >= -32099 && code <= -32020, `${name} sits in the reserved band`).toBe(false);
    }
  });

  it('never reuses the two codes the SDK already occupies', () => {
    for (const [name, code] of codeEntries()) {
      expect(code, `${name} reuses an SDK code`).not.toBe(-32001);
      expect(code, `${name} reuses an SDK code`).not.toBe(-32002);
    }
  });

  it('assigns a distinct code per class', () => {
    const codes = codeEntries().map(([, code]) => code);

    expect(new Set(codes).size).toBe(codes.length);
  });
});

/* Leaf: every relative-import form, all three quote styles. Group 1 is the specifier. */
const RELATIVE_IMPORT_FORMS: readonly RegExp[] = [
  // import x from './y'   export { x } from "./y"
  /\bfrom\s*['"`](\.[^'"`]*)['"`]/g,
  // side-effect: import './y'
  /\bimport\s*['"`](\.[^'"`]*)['"`]/g,
  // dynamic: import('./y')
  /\bimport\s*\(\s*['"`](\.[^'"`]*)['"`]/g,
  // CommonJS interop if the module ever stops being ESM
  /\brequire\s*\(\s*['"`](\.[^'"`]*)['"`]/g,
];

describe('the module', () => {
  const source = (): string =>
    readFileSync(new URL('../../src/errors.ts', import.meta.url), 'utf8');

  it('imports nothing from src/, in any quoting or import form', () => {
    const text = source();

    expect(
      text.length,
      'control: the module really was read rather than resolving empty'
    ).toBeGreaterThan(200);

    expect(
      RELATIVE_IMPORT_FORMS.length,
      'control: emptying this table would leave the loop below iterating nothing and passing'
    ).toBeGreaterThan(3);

    const relative = RELATIVE_IMPORT_FORMS.flatMap((pattern) =>
      [...text.matchAll(pattern)].map((match) => match[1] ?? '')
    );
    expect(
      relative,
      'a leaf module is importable by every layer only while it imports none'
    ).toEqual([]);
  });

  it('reaches nothing through a dynamic import this suite cannot read', () => {
    const text = source();

    expect(text.length, 'control: the module really was read').toBeGreaterThan(200);

    // Literal patterns miss a computed specifier; a leaf has no reason to import() at all.
    const dynamicImports = [...text.matchAll(/\bimport\s*\(/g)].length;
    expect(
      dynamicImports,
      'a dynamic import in a leaf module either reaches another module or is dead code, and a ' +
        'computed specifier is invisible to every pattern above'
    ).toBe(0);
  });
});
