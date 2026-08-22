import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CORRELATION_ID_HEADER,
  fetchUpstream,
  IDENTITY_DENY_LIST,
  selectDeclaredToolParameters,
} from '../../../src/upstream/client.ts';
import { expectWireCallsSince } from '../../support/assertions.ts';
import {
  installUpstreamMock,
  wireCallText,
  type UpstreamMock,
} from '../../support/upstreamMock.ts';
import { NUTRIHELP_API_ORIGIN } from '../../support/testEnv.ts';

const PROBE_PATH = '/api/ticket-28-probe';
const SMUGGLED_IDENTITY = 'SMUGGLED-IDENTITY-c0ffee';

/** Hand-written pin — must not derive from `IDENTITY_DENY_LIST`. */
const REQUIRED_IDENTITY_FIELDS = [
  'user_id',
  'userId',
  'user',
  'username',
  'useremail',
  'email',
  'identifier',
  'targetUserId',
  'targetEmail',
  'target_user_id',
  'target_email',
  'targetuser',
  'targetusername',
  'targetuseremail',
] as const;

const REQUIRED_FLOOR = 14;

const BLOCKED_TEST_FIELDS = [
  ...IDENTITY_DENY_LIST,
  'USER_ID',
  'User-Id',
  'User Name',
  'TARGET_USER_ID',
  'Target Email',
  'target.user.email',
] as const;

let upstream: UpstreamMock;

beforeEach(() => {
  upstream = installUpstreamMock([]);
  upstream.route({
    path: new RegExp(`^${PROBE_PATH}(\\?.*)?$`),
    status: 200,
    body: { ok: true },
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  await upstream.restore();
});

describe('Ticket 28 outbound identity boundary', () => {
  it('declares every required identity field, and is not silently empty', () => {
    expect(
      REQUIRED_IDENTITY_FIELDS.length,
      `The required-field table has ${String(REQUIRED_IDENTITY_FIELDS.length)} entries, below ` +
        `the floor of ${String(REQUIRED_FLOOR)}. Entries were deleted, and each one took its ` +
        `assertion with it.`
    ).toBeGreaterThanOrEqual(REQUIRED_FLOOR);

    expect(
      IDENTITY_DENY_LIST.length,
      'the deny-list and the list pinning it have diverged — add the new spelling to ' +
        'REQUIRED_IDENTITY_FIELDS, or remove it from IDENTITY_DENY_LIST'
    ).toBe(REQUIRED_IDENTITY_FIELDS.length);

    for (const field of REQUIRED_IDENTITY_FIELDS) {
      expect(
        IDENTITY_DENY_LIST as readonly string[],
        `"${field}" is stripped on the way out`
      ).toContain(field);
    }
  });

  it('forwards only parameters declared by the tool definition', async () => {
    const timeout = vi.spyOn(AbortSignal, 'timeout');
    await fetchUpstream({
      baseUrl: NUTRIHELP_API_ORIGIN,
      path: PROBE_PATH,
      declaredParameters: ['query', 'limit'],
      toolArguments: {
        query: 'apple',
        limit: 2,
        undeclaredSort: 'descending',
      },
      deadlineMs: 5_000,
      correlationId: 'declared-parameters-test',
    });
    expect(timeout).toHaveBeenCalledWith(5_000);
    const calls = expectWireCallsSince(
      upstream.callsTo(PROBE_PATH),
      0,
      'the declared request must reach the upstream wire'
    );

    for (const call of calls) {
      expect(call.searchParams).toEqual({
        query: 'apple',
        limit: '2',
      });

      const sent = new Map(
        Object.entries(call.headers).map(([name, value]) => [
          name.toLowerCase(),
          Array.isArray(value) ? value.join(', ') : value,
        ])
      );

      expect(sent.get(CORRELATION_ID_HEADER)).toBe('declared-parameters-test');
    }
  });

  it('strips and logs every blocked identity-field spelling', async () => {
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    for (const field of BLOCKED_TEST_FIELDS) {
      const before = upstream.callsTo(PROBE_PATH).length;

      await fetchUpstream({
        baseUrl: NUTRIHELP_API_ORIGIN,
        path: PROBE_PATH,
        declaredParameters: ['query', field],
        toolArguments: {
          query: 'apple',
          [field]: SMUGGLED_IDENTITY,
        },
        deadlineMs: 5_000,
        correlationId: 'identity-stripping-test',
      });

      const calls = expectWireCallsSince(
        upstream.callsTo(PROBE_PATH),
        before,
        `${field} must be stripped without stopping the request`
      );

      for (const call of calls) {
        expect(call.searchParams).toEqual({ query: 'apple' });
        expect(wireCallText(call)).not.toContain(SMUGGLED_IDENTITY);
      }

      expect(warning).toHaveBeenCalledWith(expect.stringContaining(field));
    }

    expect(warning).toHaveBeenCalledTimes(BLOCKED_TEST_FIELDS.length);
    expect(warning).not.toHaveBeenCalledWith(expect.stringContaining(SMUGGLED_IDENTITY));
  });
  it('truncates field names and caps warnings without weakening stripping', () => {
    const longField = `u${'-'.repeat(100_000)}ser`;
    const fields = [
      longField,
      ...Array.from({ length: 24 }, (_, index) => `u${'-'.repeat(index + 1)}ser`),
    ];

    const toolArguments = Object.fromEntries(fields.map((field) => [field, SMUGGLED_IDENTITY]));
    const loggedFields: string[] = [];

    const selected = selectDeclaredToolParameters(toolArguments, fields, (event) =>
      loggedFields.push(event.field)
    );

    expect(fields).toHaveLength(25);
    expect(selected).toEqual({});
    expect(loggedFields).toHaveLength(20);
    expect(loggedFields[0]).toBe(longField.slice(0, 128));
  });
  it('rejects a path that changes the configured origin', async () => {
    await expect(
      fetchUpstream({
        baseUrl: NUTRIHELP_API_ORIGIN,
        path: '//attacker.example/steal',
        declaredParameters: [],
        deadlineMs: 5_000,
        correlationId: 'origin-test',
      })
    ).rejects.toThrow('Upstream path must remain on the configured origin');
  });

  it('rejects a query or fragment embedded in the path', async () => {
    for (const path of [
      `${PROBE_PATH}?user_id=${SMUGGLED_IDENTITY}`,
      `${PROBE_PATH}#${SMUGGLED_IDENTITY}`,
    ]) {
      await expect(
        fetchUpstream({
          baseUrl: NUTRIHELP_API_ORIGIN,
          path,
          declaredParameters: [],
          deadlineMs: 5_000,
          correlationId: 'embedded-path-data-test',
        })
      ).rejects.toThrow('Upstream path must not include a query or fragment');
    }
  });

  it('rejects a client-supplied identity interpolated into the path', async () => {
    await expect(
      fetchUpstream({
        baseUrl: NUTRIHELP_API_ORIGIN,
        path: `/api/recipe/user/${encodeURIComponent(SMUGGLED_IDENTITY)}`,
        declaredParameters: ['user_id'],
        toolArguments: {
          user_id: SMUGGLED_IDENTITY,
        },
        deadlineMs: 5_000,
        correlationId: 'identity-path-test',
      })
    ).rejects.toThrow('Client-supplied identity must not appear in the upstream path');
  });

  it('rejects a percent-encoded identity in the path', async () => {
    const encodedIdentity = 'a b/c';

    await expect(
      fetchUpstream({
        baseUrl: NUTRIHELP_API_ORIGIN,
        path: `/api/recipe/user/${encodeURIComponent(encodedIdentity)}`,
        declaredParameters: [],
        toolArguments: { user_id: encodedIdentity },
        deadlineMs: 5_000,
        correlationId: 'encoded-identity-path-test',
      })
    ).rejects.toThrow('Client-supplied identity must not appear in the upstream path');
  });

  it('decides rather than throwing URIError on a malformed percent escape', async () => {
    const malformedPath = `${PROBE_PATH}/100%`;
    upstream.route({ path: /^\/api\/ticket-28-probe\//, status: 200, body: { ok: true } });

    const before = upstream.callsTo(malformedPath).length;

    await expect(
      fetchUpstream({
        baseUrl: NUTRIHELP_API_ORIGIN,
        path: malformedPath,
        declaredParameters: ['query'],
        toolArguments: { query: 'apple' },
        deadlineMs: 5_000,
        correlationId: 'malformed-escape-test',
      })
    ).resolves.toBeDefined();

    expectWireCallsSince(
      upstream.callsTo(malformedPath),
      before,
      'a path carrying a malformed escape must still reach the wire'
    );
  });

  it('refuses a deadline AbortSignal.timeout cannot honour, before reaching the wire', async () => {
    for (const deadlineMs of [
      0,
      -1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
    ]) {
      const before = upstream.callsTo(PROBE_PATH).length;

      await expect(
        fetchUpstream({
          baseUrl: NUTRIHELP_API_ORIGIN,
          path: PROBE_PATH,
          declaredParameters: [],
          deadlineMs,
          correlationId: 'deadline-guard-test',
        })
      ).rejects.toThrow('Upstream deadline must be a positive finite number of milliseconds');

      expect(
        upstream.callsTo(PROBE_PATH).length,
        `deadlineMs=${String(deadlineMs)} must be refused before anything is sent`
      ).toBe(before);
    }
  });

  it('still permits an explicitly absent deadline', async () => {
    const timeout = vi.spyOn(AbortSignal, 'timeout');
    const before = upstream.callsTo(PROBE_PATH).length;

    await fetchUpstream({
      baseUrl: NUTRIHELP_API_ORIGIN,
      path: PROBE_PATH,
      declaredParameters: [],
      deadlineMs: undefined,
      correlationId: 'absent-deadline-test',
    });

    expectWireCallsSince(upstream.callsTo(PROBE_PATH), before, 'the request must still be sent');
    expect(timeout).not.toHaveBeenCalled();
  });
});
