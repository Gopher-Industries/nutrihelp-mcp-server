import { describe, expect, it, vi } from 'vitest';
import { descriptor, handler } from '../../../src/tools/getMealPlan.ts';

interface CredentialRequest {
  readonly accessToken: string;
  readonly url: URL;
}

const getWithCredentialMock = vi.hoisted(() => vi.fn());

vi.mock('../../../src/upstream/client.ts', () => ({
  getWithCredential: getWithCredentialMock,
}));

describe('get_meal_plan', () => {
  const config = {
    nutrihelpApiBaseUrl: 'https://api.nutrihelp.test',
    requestDeadlineMs: 30_000,
  };

  it('sends only the verified token and keeps two users isolated', async () => {
    getWithCredentialMock.mockImplementation(({ accessToken }: CredentialRequest) => {
      const meals =
        accessToken === 'token-user-a'
          ? [
              {
                date: '2026-09-15',
                meal_slot: 'breakfast',
                recipe_id: 'recipe-a',
                recipe_name: 'User A Breakfast',
                energy: 400,
              },
            ]
          : [
              {
                date: '2026-09-15',
                meal_slot: 'breakfast',
                recipe_id: 'recipe-b',
                recipe_name: 'User B Breakfast',
                energy: 500,
              },
            ];

      return Promise.resolve(
        new Response(JSON.stringify(meals), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      );
    });

    const userAResult = await handler(
      config,
      'token-user-a'
    )({
      date: '2026-09-15',
    });

    const userBResult = await handler(
      config,
      'token-user-b'
    )({
      date: '2026-09-15',
    });

    expect(getWithCredentialMock).toHaveBeenCalledTimes(2);

    const calls = getWithCredentialMock.mock.calls;
    const firstCall = calls[0]?.[0] as CredentialRequest;
    const secondCall = calls[1]?.[0] as CredentialRequest;

    expect(firstCall.accessToken).toBe('token-user-a');
    expect(secondCall.accessToken).toBe('token-user-b');

    expect(String(firstCall.url)).toBe(
      'https://api.nutrihelp.test/api/mealplan/me?date=2026-09-15'
    );

    expect(String(secondCall.url)).toBe(
      'https://api.nutrihelp.test/api/mealplan/me?date=2026-09-15'
    );

    expect(String(firstCall.url)).not.toContain('user_id');
    expect(String(firstCall.url)).not.toContain('userId');
    expect(String(secondCall.url)).not.toContain('user_id');
    expect(String(secondCall.url)).not.toContain('userId');

    expect(userAResult.structuredContent).toEqual({
      meals: [
        {
          date: '2026-09-15',
          meal_slot: 'breakfast',
          recipe_id: 'recipe-a',
          recipe_name: 'User A Breakfast',
          energy: 400,
        },
      ],
    });

    expect(userBResult.structuredContent).toEqual({
      meals: [
        {
          date: '2026-09-15',
          meal_slot: 'breakfast',
          recipe_id: 'recipe-b',
          recipe_name: 'User B Breakfast',
          energy: 500,
        },
      ],
    });

    expect(userAResult.structuredContent).not.toEqual(userBResult.structuredContent);
  });

  it('does not expose a user ID in the tool input schema', () => {
    const result = descriptor.inputSchema.safeParse({
      date: '2026-09-15',
      meal_type: 'breakfast',
      user_id: 'another-user',
    });

    expect(result.success).toBe(true);

    if (result.success) {
      expect(result.data).not.toHaveProperty('user_id');
    }
  });
});
