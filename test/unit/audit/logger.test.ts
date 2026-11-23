import { createHash, generateKeyPairSync } from 'node:crypto';
import { decodeJwt, jwtVerify } from 'jose';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuditWriter, type AuditEvent } from '../../../src/audit/logger.ts';
import { postAuditEnvelope } from '../../../src/upstream/client.ts';

vi.mock('../../../src/upstream/client.ts', () => ({ postAuditEnvelope: vi.fn() }));
const post = vi.mocked(postAuditEnvelope);
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const url = 'https://backend.example.test/api/security-events/mcp';
const service = 'https://mcp.example.test/client';
const write = createAuditWriter(url, service, privateKey);
const start: AuditEvent = {
  schema_version: 1,
  phase: 'started',
  event_id: crypto.randomUUID(),
  correlation_id: crypto.randomUUID(),
  grant_id: crypto.randomUUID(),
  user_id: '42',
  client_id: 'https://assistant.example.test',
  tool: 'nutrition_lookup',
  scope: 'nutrition:read',
  timestamp: new Date().toISOString(),
  argument_hash: 'a'.repeat(64),
  introspection: 'active',
  confirmation: 'not_required',
};
const done: AuditEvent = {
  ...start,
  phase: 'completion',
  exchange: 'not_required',
  outcome: 'success',
  latency_ms: 20,
  upstream_status_class: '2xx',
};
const ack = (event_id: string, phase: string) => ({
  success: true,
  data: { acknowledged: [{ event_id, phase }] },
});
beforeEach(() => post.mockReset());
describe('direct audit acknowledgements', () => {
  it.each([
    undefined,
    {},
    ack(crypto.randomUUID(), 'started'),
    ack(start.event_id, 'completion'),
    { success: false, data: { acknowledged: [{ event_id: start.event_id, phase: 'started' }] } },
  ])('refuses an unrelated or incomplete start acknowledgement', async (reply) => {
    post.mockResolvedValue(reply);
    await expect(write(start, () => 1000)).rejects.toThrow('unacknowledged');
    expect(post).toHaveBeenCalledTimes(1);
  });
  it('authenticates the exact stored bytes, audience and service identity', async () => {
    post.mockResolvedValue(ack(start.event_id, 'started'));
    await write(start, () => 1000);
    const first = post.mock.calls[0];
    if (!first) throw new Error('expected one audit request');
    const [target, body, token] = first;
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: service,
      subject: service,
      audience: url,
      algorithms: ['RS256'],
    });
    expect(target).toBe(url);
    expect(JSON.parse(body)).toEqual({ events: [start] });
    expect(payload.body_sha256).toBe(createHash('sha256').update(body).digest('hex'));
  });
  it('retries only the same completion bytes using a fresh assertion', async () => {
    post
      .mockRejectedValueOnce(new Error('unavailable'))
      .mockResolvedValueOnce(ack(done.event_id, 'started'))
      .mockResolvedValueOnce(ack(done.event_id, 'completion'));
    await write(done, () => 1200);
    expect(post).toHaveBeenCalledTimes(3);
    expect(new Set(post.mock.calls.map((call) => call[1])).size).toBe(1);
    expect(new Set(post.mock.calls.map((call) => decodeJwt(call[2]).jti)).size).toBe(3);
  });
  it('stops when the budget or the completion retry limit is exhausted', async () => {
    post.mockResolvedValue({});
    await expect(write(done, () => 0)).rejects.toThrow('unacknowledged');
    expect(post).not.toHaveBeenCalled();
    await expect(write(done, () => 1000)).rejects.toThrow('unacknowledged');
    expect(post).toHaveBeenCalledTimes(3);
  });
});
