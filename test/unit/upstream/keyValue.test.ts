import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock('@redis/client', () => ({ createClient: mocks.createClient }));

import { connectKeyValue } from '../../../src/upstream/client.ts';
import { connectConfirmationStore } from '../../../src/auth/confirmationStore.ts';

function fakeClient() {
  return {
    isOpen: true,
    on: vi.fn(),
    connect: vi.fn<() => Promise<void>>().mockResolvedValue(undefined),
    eval: vi.fn().mockResolvedValue(['claimed']),
    withCommandOptions: vi.fn(),
    destroy: vi.fn(),
  };
}

let client: ReturnType<typeof fakeClient>;

beforeEach(() => {
  vi.clearAllMocks();
  client = fakeClient();
  client.withCommandOptions.mockReturnValue(client);
  mocks.createClient.mockReturnValue(client);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('Key Value egress', () => {
  it('disables offline queuing and passes a deadline to every command', async () => {
    const connection = await connectKeyValue('rediss://host:6379', 500);
    expect(mocks.createClient).toHaveBeenCalledWith({
      url: 'rediss://host:6379',
      disableOfflineQueue: true,
      socket: { connectTimeout: 500, reconnectStrategy: false },
    });
    expect(client.on).toHaveBeenCalledWith('error', expect.any(Function));
    expect(await connection.eval('return 1', ['key'], ['arg'], 100)).toEqual(['claimed']);
    expect(client.withCommandOptions).toHaveBeenCalledWith({ timeout: 100 });
    expect(client.eval).toHaveBeenCalledWith('return 1', { keys: ['key'], arguments: ['arg'] });
    connection.close();
    expect(client.destroy).toHaveBeenCalledTimes(1);
  });

  it.each(['not a URL', 'https://host', 'redis://host?secret=value', 'redis://host#secret'])(
    'refuses invalid connection settings %s',
    async (url) => {
      await expect(connectKeyValue(url, 100)).rejects.toThrow('Invalid Key Value configuration');
      expect(mocks.createClient).not.toHaveBeenCalled();
    }
  );

  it('sanitizes synchronous driver configuration errors', async () => {
    mocks.createClient.mockImplementationOnce(() => {
      throw new Error('secret-url');
    });
    await expect(connectKeyValue('redis://host', 100)).rejects.toThrow(
      'Invalid Key Value configuration'
    );
  });

  it('sanitizes connection errors and closes the failed connection', async () => {
    client.connect.mockRejectedValue(new Error('credential from Redis URL'));
    await expect(connectKeyValue('redis://host', 100)).rejects.toThrow(
      'Key Value connection unavailable'
    );
    expect(client.destroy).toHaveBeenCalledTimes(1);
  });

  it('bounds the complete handshake, not just the initial TCP connect', async () => {
    vi.useFakeTimers();
    client.connect.mockReturnValue(
      new Promise(() => {
        /* No handshake response. */
      })
    );
    const attempt = expect(connectKeyValue('redis://host', 100)).rejects.toThrow(
      'Key Value connection unavailable'
    );
    await vi.advanceTimersByTimeAsync(100);
    await attempt;
    expect(client.destroy).toHaveBeenCalledTimes(1);
  });

  it('sanitizes command errors without preserving Redis arguments', async () => {
    const connection = await connectKeyValue('redis://host', 100);
    client.eval.mockRejectedValue(new Error('sensitive command arguments'));
    await expect(connection.eval('script', [], [], 50)).rejects.toThrow(
      'Key Value command unavailable'
    );
    connection.close();
  });

  it('refuses a spent command budget before queuing anything', async () => {
    const connection = await connectKeyValue('redis://host', 100);
    await expect(connection.eval('script', [], [], 0)).rejects.toThrow(TypeError);
    expect(client.eval).not.toHaveBeenCalled();
    client.isOpen = false;
    connection.close();
    expect(client.destroy).not.toHaveBeenCalled();
  });

  it('closes the connection if store options are invalid', async () => {
    await expect(connectConfirmationStore('redis://host', { lifetimeMs: 0 })).rejects.toThrow(
      TypeError
    );
    expect(client.destroy).toHaveBeenCalledTimes(1);
  });
});
