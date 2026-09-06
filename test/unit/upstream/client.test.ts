import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CORRELATION_ID_HEADER,
  fetchUpstream,
  IDENTITY_DENY_LIST,
  postFormWithoutCredential,
  selectDeclaredToolParameters,
  type FormPostOptions,
} from '../../../src/upstream/client.ts';
import { expectWireCallsSince } from '../../support/assertions.ts';
import {
  installUpstreamMock,
  wireCallText,
  type UpstreamMock,
} from '../../support/upstreamMock.ts';
import { NUTRIHELP_API_ORIGIN } from '../../support/testEnv.ts';

const PROBE_PATH = '/api/ticket-28-probe';
const FORM_PROBE_PATH = '/api/ticket-59-form-probe';
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
  upstream.route({
    path: FORM_PROBE_PATH,
    method: 'POST',
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

/**
 * Ticket 59 form POST for auth-server endpoints. No `Authorization` header (`private_key_jwt`
 * in the body). Refuses identity fields loudly rather than stripping them.
 */
describe('the unauthenticated form POST', () => {
  it('sends a form-encoded body with the correlation id and no credential header', async () => {
    const before = upstream.callsTo(FORM_PROBE_PATH).length;

    await postFormWithoutCredential({
      url: `${NUTRIHELP_API_ORIGIN}${FORM_PROBE_PATH}`,
      form: { token: 'token-value.with.dots', token_type_hint: 'access_token' },
      deadlineMs: 5_000,
      correlationId: 'form-post-test',
      redirect: 'error',
    });

    const calls = expectWireCallsSince(
      upstream.callsTo(FORM_PROBE_PATH),
      before,
      'the form POST must reach the wire'
    );

    for (const call of calls) {
      expect(call.method).toBe('POST');

      const sent = new Map(
        Object.entries(call.headers).map(([name, value]) => [
          name.toLowerCase(),
          Array.isArray(value) ? value.join(', ') : value,
        ])
      );
      expect(sent.get('content-type')).toContain('application/x-www-form-urlencoded');
      expect(sent.get(CORRELATION_ID_HEADER)).toBe('form-post-test');
      expect(
        sent.get('authorization'),
        'the authorization-server endpoints authenticate this server by the assertion in the body'
      ).toBeUndefined();
      expect(sent.get('cookie')).toBeUndefined();

      const form = new URLSearchParams(call.body);
      expect(form.get('token')).toBe('token-value.with.dots');
      expect(form.get('token_type_hint')).toBe('access_token');
      expect([...form.keys()].sort(), 'the body is exactly what the caller named').toEqual([
        'token',
        'token_type_hint',
      ]);
      expect(call.searchParams, 'nothing is smuggled into the query string').toEqual({});
    }
  });

  it('refuses every blocked identity spelling before anything is sent', async () => {
    for (const field of BLOCKED_TEST_FIELDS) {
      const before = upstream.wireCalls().length;

      await expect(
        postFormWithoutCredential({
          url: `${NUTRIHELP_API_ORIGIN}${FORM_PROBE_PATH}`,
          form: { token: 'token-value', [field]: SMUGGLED_IDENTITY },
          deadlineMs: 5_000,
          correlationId: 'form-identity-test',
          redirect: 'error',
        }),
        `${field} must fail loudly here rather than being stripped in silence`
      ).rejects.toThrow(TypeError);

      expect(
        upstream.wireCalls().length,
        `${field}: the refusal happens before the request, so nothing reaches the wire at all`
      ).toBe(before);
    }
  });

  /**
   * No unbounded form of this call. Table pins values a caller can pass; absent deadline is
   * refused by the type, not listed here. Key-set GET keeps its own optional-deadline contract.
   */
  const UNUSABLE_DEADLINES = [
    0,
    -1,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
  ] as const;

  it('has more than one unusable shape, and the table is not empty', () => {
    expect(
      UNUSABLE_DEADLINES.length,
      'emptying this table would delete every deadline refusal in silence'
    ).toBeGreaterThanOrEqual(5);
  });

  it.each(UNUSABLE_DEADLINES)(
    'refuses the deadline %p before reaching the wire',
    async (deadlineMs) => {
      const before = upstream.wireCalls().length;

      const attempt = postFormWithoutCredential({
        url: `${NUTRIHELP_API_ORIGIN}${FORM_PROBE_PATH}`,
        form: { token: 'token-value' },
        deadlineMs,
        correlationId: 'form-deadline-test',
        redirect: 'error',
      });

      await expect(attempt).rejects.toThrow(TypeError);
      await expect(
        attempt,
        'refused by the guard that has no absent-deadline arm, not by the one that does'
      ).rejects.toThrow('Authorization-server calls require a positive finite deadline');

      expect(
        upstream.wireCalls().length,
        `deadlineMs=${String(deadlineMs)}: an authorization-server call that cannot be bounded reaches no endpoint at all`
      ).toBe(before);
    }
  );

  /**
   * Positive control for the table above. Without it, "nothing reached the wire" also passes
   * against a helper that never sends.
   */
  it('applies a usable caller deadline to the request it sends', async () => {
    const timeout = vi.spyOn(AbortSignal, 'timeout');
    const before = upstream.wireCalls().length;

    await postFormWithoutCredential({
      url: `${NUTRIHELP_API_ORIGIN}${FORM_PROBE_PATH}`,
      form: { token: 'token-value' },
      deadlineMs: 1_500,
      correlationId: 'form-deadline-applied-test',
      redirect: 'error',
    });

    expectWireCallsSince(
      upstream.callsTo(FORM_PROBE_PATH),
      before,
      'a usable deadline sends the request, so the refusals above are refusals rather than a helper that never sends'
    );
    expect(timeout, 'the remaining request budget is what bounds this call').toHaveBeenCalledWith(
      1_500
    );
  });

  /**
   * Compile-level pin: if `deadlineMs` widens to `number | undefined`, this resolves to `never`
   * and typecheck fails. Runtime tables cannot reach an unexpressible value.
   */
  type DeadlineIsRequired = undefined extends FormPostOptions['deadlineMs'] ? never : true;

  it('cannot express an absent deadline at all', () => {
    const deadlineIsRequired: DeadlineIsRequired = true;

    expect(
      deadlineIsRequired,
      'the real assertion is the type above; this keeps the pin visible in the run'
    ).toBe(true);
  });
});
