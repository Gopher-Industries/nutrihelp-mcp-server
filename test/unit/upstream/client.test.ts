import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fetchUpstream, IDENTITY_DENY_LIST } from '../../../src/upstream/client.ts';
import { expectWireCallsSince } from '../../support/assertions.ts';
import {
  installUpstreamMock,
  wireCallText,
  type UpstreamMock,
} from '../../support/upstreamMock.ts';
import { NUTRIHELP_API_ORIGIN } from '../../support/testEnv.ts';

const PROBE_PATH = '/api/ticket-28-probe';
const SMUGGLED_IDENTITY = 'SMUGGLED-IDENTITY-c0ffee';

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
  it('forwards only parameters declared by the tool definition', async () => {
    await fetchUpstream({
      baseUrl: NUTRIHELP_API_ORIGIN,
      path: PROBE_PATH,
      declaredParameters: ['query', 'limit'],
      toolArguments: {
        query: 'apple',
        limit: 2,
        undeclaredSort: 'descending',
      },
    });

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
});
