import { EventEmitter } from 'node:events';
import { generateKeyPairSync } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ServerConfig } from '../../src/config/index.ts';
import { startServer } from '../../src/server.ts';
import { loadConfig } from '../../src/config/index.ts';
import { connectKeyValue } from '../../src/upstream/client.ts';
import { createHttpApp } from '../../src/transport/http.ts';
import { createConfirmationStore } from '../../src/consent/confirmation.ts';
import { registerTools } from '../../src/tools/registry.ts';
import { unavailableConfirmations } from '../support/confirmationFixture.ts';

vi.mock('../../src/config/index.ts', () => ({ loadConfig: vi.fn() }));
vi.mock('../../src/upstream/client.ts', () => ({ connectKeyValue: vi.fn() }));
vi.mock('../../src/transport/http.ts', () => ({ createHttpApp: vi.fn() }));
vi.mock('../../src/consent/confirmation.ts', () => ({ createConfirmationStore: vi.fn() }));
vi.mock('../../src/tools/registry.ts', () => ({
  registerTools: vi.fn(),
  AUDIT_ENQUEUE_NOT_IMPLEMENTED: vi.fn(),
}));
vi.mock('../../src/auth/tokenValidator.ts', () => ({ createTokenValidator: vi.fn() }));
vi.mock('../../src/auth/revocation.ts', () => ({ createRevocationChecker: vi.fn() }));
vi.mock('../../src/auth/upstreamToken.ts', () => ({ createUpstreamCredentialProvider: vi.fn() }));

const config: ServerConfig = {
  confirmationStore: 'shared',
  redisUrl: 'redis://127.0.0.1:16489',
  port: 3000,
  allowedOriginHostnames: ['client.test'],
  nutrihelpApiBaseUrl: 'https://api.nutrihelp.test',
  jwksUrl: new URL('https://auth.nutrihelp.test/jwks'),
  expectedIssuer: 'https://auth.nutrihelp.test',
  authServerUrl: 'https://auth.nutrihelp.test',
  resourceIdentifier: 'https://mcp.nutrihelp.test/mcp',
  jwksCacheMaxAgeMs: 300000,
  requestDeadlineMs: 30000,
  clientId: 'https://mcp.nutrihelp.test/client',
  clientAssertionKey: generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey,
  revokedGrantCacheMaxAgeMs: 0,
};
let listener: EventEmitter & { close: ReturnType<typeof vi.fn<() => void>> };
let closeRedis: ReturnType<typeof vi.fn<() => void>>;
let listen: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(loadConfig).mockReturnValue(config);
  closeRedis = vi.fn();
  vi.mocked(connectKeyValue).mockResolvedValue({ eval: vi.fn(), close: closeRedis });
  vi.mocked(createConfirmationStore).mockReturnValue(unavailableConfirmations);
  listener = Object.assign(new EventEmitter(), {
    close: vi.fn(() => {
      listener.emit('close');
    }),
  });
  listen = vi.fn((_port: number, ready: () => void) => {
    ready();
    return listener;
  });
  vi.mocked(createHttpApp).mockReturnValue({ listen } as unknown as ReturnType<
    typeof createHttpApp
  >);
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  vi.spyOn(console, 'log').mockImplementation(() => undefined);
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
});
afterEach(() => {
  listener.emit('close');
  vi.restoreAllMocks();
});

describe('shared confirmation store lifecycle', () => {
  it('opens before listen with a lease strictly longer than the request deadline', async () => {
    await startServer();
    expect(connectKeyValue).toHaveBeenCalledWith(config.redisUrl, 1000);
    const options = vi.mocked(createConfirmationStore).mock.calls[0]?.[1];
    expect(options?.leaseMs).toBeGreaterThan(config.requestDeadlineMs);
    expect(vi.mocked(connectKeyValue).mock.invocationCallOrder[0]).toBeLessThan(
      listen.mock.invocationCallOrder[0] ?? 0
    );
    expect(listen).toHaveBeenCalledTimes(1);
  });
  it('does not listen when Redis cannot connect', async () => {
    vi.mocked(connectKeyValue).mockRejectedValueOnce(new Error('private password'));
    await expect(startServer()).rejects.toMatchObject({ code: 'confirmation_store_unavailable' });
    expect(listen).not.toHaveBeenCalled();
    expect(createHttpApp).not.toHaveBeenCalled();
  });
  it('closes Redis if store construction fails', async () => {
    vi.mocked(createConfirmationStore).mockImplementationOnce(() => {
      throw new Error('invalid options');
    });
    await expect(startServer()).rejects.toThrow('invalid options');
    expect(closeRedis).toHaveBeenCalledTimes(1);
    expect(listen).not.toHaveBeenCalled();
  });
  it('closes Redis if transport construction fails', async () => {
    vi.mocked(createHttpApp).mockImplementationOnce(() => {
      throw new Error('transport');
    });
    await expect(startServer()).rejects.toThrow('transport');
    expect(closeRedis).toHaveBeenCalledTimes(1);
  });
  it('closes Redis on listener shutdown and removes signal hooks', async () => {
    const before = process.listenerCount('SIGTERM');
    await startServer();
    expect(process.listenerCount('SIGTERM')).toBe(before + 1);
    listener.close();
    expect(closeRedis).toHaveBeenCalledTimes(1);
    expect(process.listenerCount('SIGTERM')).toBe(before);
  });
  it('closes Redis after a listen error', async () => {
    await startServer();
    listener.emit('error', new Error('address in use'));
    expect(closeRedis).toHaveBeenCalledTimes(1);
  });
  it('wires the opened store into the registry with a separate anomaly sink', async () => {
    await startServer();
    const options = vi.mocked(createHttpApp).mock.calls[0]?.[0];
    if (!options) throw new Error('Missing app options');
    const lookup = () => undefined;
    await options.factory({} as Parameters<typeof registerTools>[1], lookup);
    const registryConfig = vi.mocked(registerTools).mock.calls[0]?.[2];
    expect(registryConfig?.confirmations.issue).toBe(unavailableConfirmations.issue);
    expect(registryConfig?.authorizationFor).toBe(lookup);
    registryConfig?.logConfirmationAnomaly({
      detailCode: 'confirmation_mismatch',
      tool: 'record_meal',
      grantId: 'g',
      correlationId: 'c',
    });
    expect(console.error).toHaveBeenCalledWith(
      JSON.stringify({
        level: 'warn',
        channel: 'security',
        detailCode: 'confirmation_mismatch',
        tool: 'record_meal',
        grantId: 'g',
        correlationId: 'c',
      })
    );
  });
});
