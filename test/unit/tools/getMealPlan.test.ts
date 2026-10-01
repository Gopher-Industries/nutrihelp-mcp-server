import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpError } from '../../../src/errors.ts';
import { descriptor, handler } from '../../../src/tools/getMealPlan.ts';

describe('get_meal_plan', () => {
  const baseRequest = {
    nutrihelpApiBaseUrl: 'https://api.nutrihelp.test',
    remainingBudgetMs: () => 30_000,
    correlationId: 'test-correlation-id',
  };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('uses the real upstream client path and keeps two users isolated', async () => {
    const fetchMock = vi.fn();

    fetchMock
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              items: [
                {
                  date: '2026-09-15',
                  meal_type: 'breakfast',
                  recipe_id: 1,
                  recipe_name: 'User A Breakfast',
                  energy_kj: 400,
                },
              ],
            },
          }),
          {
            status: 200,
            headers: {
              'content-type': 'application/json',
            },
          }
        )
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            data: {
              items: [
                {
                  date: '2026-09-15',
                  meal_type: 'breakfast',
                  recipe_id: 2,
                  recipe_name: 'User B Breakfast',
                  energy_kj: 500,
                },
              ],
            },
          }),
          {
            status: 200,
            headers: {
              'content-type': 'application/json',
            },
          }
        )
      );

    vi.stubGlobal('fetch', fetchMock);

    const userAResult = await handler({
      ...baseRequest,
      credential: {
        accessToken: 'token-user-a',
      },
    })({
      date: '2026-09-15',
    });

    const userBResult = await handler({
      ...baseRequest,
      credential: {
        accessToken: 'token-user-b',
      },
    })({
      date: '2026-09-15',
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);

    const firstCall = fetchMock.mock.calls[0];
    const secondCall = fetchMock.mock.calls[1];

    expect(String(firstCall?.[0])).toBe('https://api.nutrihelp.test/api/mealplan/?date=2026-09-15');

    expect(String(secondCall?.[0])).toBe(
      'https://api.nutrihelp.test/api/mealplan/?date=2026-09-15'
    );

    const firstInit = firstCall?.[1] as RequestInit;
    const secondInit = secondCall?.[1] as RequestInit;

    expect(new Headers(firstInit.headers).get('authorization')).toBe('Bearer token-user-a');

    expect(new Headers(secondInit.headers).get('authorization')).toBe('Bearer token-user-b');

    expect(String(firstCall?.[0])).not.toContain('user_id');
    expect(String(firstCall?.[0])).not.toContain('userId');

    expect(String(secondCall?.[0])).not.toContain('user_id');
    expect(String(secondCall?.[0])).not.toContain('userId');

    expect(userAResult.structuredContent).toEqual({
      date: '2026-09-15',
      entries: [
        {
          date: '2026-09-15',
          meal_slot: 'breakfast',
          recipe_id: 1,
          recipe_name: 'User A Breakfast',
          energy: 400,
        },
      ],
      total_available: 1,
    });

    expect(userBResult.structuredContent).toEqual({
      date: '2026-09-15',
      entries: [
        {
          date: '2026-09-15',
          meal_slot: 'breakfast',
          recipe_id: 2,
          recipe_name: 'User B Breakfast',
          energy: 500,
        },
      ],
      total_available: 1,
    });

    expect(userAResult.structuredContent).not.toEqual(userBResult.structuredContent);

    expect(JSON.stringify(userAResult.structuredContent)).not.toContain('User B Breakfast');

    expect(JSON.stringify(userBResult.structuredContent)).not.toContain('User A Breakfast');
  });

  it('bounds oversized results with truncation metadata', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            items: Array.from({ length: 500 }, (_, index) => ({
              date: '2026-09-15',
              meal_type: 'breakfast',
              recipe_id: index,
              recipe_name: `Recipe ${String(index)}`,
              energy_kj: 400,
            })),
          },
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        }
      )
    );

    vi.stubGlobal('fetch', fetchMock);

    const result = await handler({
      ...baseRequest,
      credential: {
        accessToken: 'token-user-a',
      },
    })({
      date: '2026-09-15',
    });

    const output = result.structuredContent as Record<string, unknown>;

    expect(output.date).toBe('2026-09-15');
    expect(output.total_available).toBe(500);
    expect(output.truncated).toBe(true);

    expect(output).toHaveProperty('truncation_note');

    expect(typeof output.truncation_note).toBe('string');

    expect((output.entries as unknown[]).length).toBeLessThanOrEqual(6);
  });

  it('returns a typed upstream failure when the exchanged credential is missing', async () => {
    await expect(
      handler({
        ...baseRequest,
        credential: undefined,
      })({
        date: '2026-09-15',
      })
    ).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });

  it('returns a typed upstream failure for a backend error', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('unavailable', {
        status: 503,
      })
    );

    vi.stubGlobal('fetch', fetchMock);

    await expect(
      handler({
        ...baseRequest,
        credential: {
          accessToken: 'token-user-a',
        },
      })({
        date: '2026-09-15',
      })
    ).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });

  it('preserves an existing typed upstream failure from the upstream client', async () => {
    const upstreamFailure = new McpError({
      class: 'upstream_failure',
      statusClass: 'timeout',
      errorCode: 'request_deadline_exhausted',
      endpointClass: 'meal-plan',
      correlationId: baseRequest.correlationId,
      latencyMs: 0,
    });

    await expect(
      handler({
        ...baseRequest,
        credential: {
          accessToken: 'token-user-a',
        },
        remainingBudgetMs: () => {
          throw upstreamFailure;
        },
      })({
        date: '2026-09-15',
      })
    ).rejects.toBe(upstreamFailure);
  });

  it('classifies a backend 4xx as an upstream failure', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('bad request', {
        status: 400,
      })
    );

    vi.stubGlobal('fetch', fetchMock);

    await expect(
      handler({
        ...baseRequest,
        credential: {
          accessToken: 'token-user-a',
        },
      })({
        date: '2026-09-15',
      })
    ).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });

  it('returns a typed upstream failure for invalid backend JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response('{not-json', {
        status: 200,
        headers: {
          'content-type': 'application/json',
        },
      })
    );

    vi.stubGlobal('fetch', fetchMock);

    await expect(
      handler({
        ...baseRequest,
        credential: {
          accessToken: 'token-user-a',
        },
      })({
        date: '2026-09-15',
      })
    ).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });

  it('returns a typed upstream failure for a response outside the backend contract', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            wrong_key: [],
          },
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        }
      )
    );

    vi.stubGlobal('fetch', fetchMock);

    await expect(
      handler({
        ...baseRequest,
        credential: {
          accessToken: 'token-user-a',
        },
      })({
        date: '2026-09-15',
      })
    ).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });

  it('keeps truncation metadata when one projected entry would exceed the byte ceiling', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          data: {
            items: Array.from({ length: 6 }, (_, index) => ({
              date: '2026-09-15',
              meal_type: 'breakfast',
              recipe_id: index,
              recipe_name: 'x'.repeat(5500),
              energy_kj: 400,
            })),
          },
        }),
        {
          status: 200,
          headers: {
            'content-type': 'application/json',
          },
        }
      )
    );

    vi.stubGlobal('fetch', fetchMock);

    const result = await handler({
      ...baseRequest,
      credential: {
        accessToken: 'token-user-a',
      },
    })({
      date: '2026-09-15',
    });

    const output = result.structuredContent as Record<string, unknown>;

    expect(output.truncated).toBe(true);
    expect(output.total_available).toBe(6);
    expect(output).toHaveProperty('truncation_note');

    expect((output.entries as unknown[]).length).toBeLessThan(6);
  });

  it('does not accept a user ID in the tool input schema', () => {
    const result = descriptor.inputSchema.safeParse({
      date: '2026-09-15',
      meal_type: 'breakfast',
      user_id: 'another-user',
    });

    expect(result.success).toBe(false);
  });

  it('rejects an unsupported meal type before any upstream call', () => {
    const fetchMock = vi.fn();

    vi.stubGlobal('fetch', fetchMock);

    const parsed = descriptor.inputSchema.safeParse({
      date: '2026-09-15',
      meal_type: 'brunch',
    });

    expect(parsed.success).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
