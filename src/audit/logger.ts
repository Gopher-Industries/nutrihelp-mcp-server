import type { KeyObject } from 'node:crypto';
import { clientAssertion } from '../auth/upstreamToken.ts';
import { McpError } from '../errors.ts';
import { canonicalJson, sha256 } from '../consent/confirmation.ts';
import { postAuditEnvelope } from '../upstream/client.ts';
import { z } from 'zod';

interface Common {
  schema_version: 1;
  event_id: string;
  timestamp: string;
  correlation_id: string;
  grant_id: string;
  user_id: string;
  client_id: string;
  tool: string;
  scope: string;
  argument_hash: string;
  introspection: 'active';
  confirmation: 'required' | 'confirmed' | 'not_required';
}
export type AuditEvent = Common &
  (
    | { phase: 'started' }
    | {
        phase: 'completion';
        outcome: 'success' | 'failure';
        exchange: 'succeeded' | 'failed' | 'not_attempted' | 'not_required';
        upstream_status_class: '2xx' | '3xx' | '4xx' | '5xx' | null;
        latency_ms: number;
      }
  );
export type AuditWriter = (event: AuditEvent, remaining: () => number) => Promise<void>;

export function argumentHash(args: unknown): string {
  try {
    return sha256(canonicalJson(args));
  } catch {
    throw new McpError({
      class: 'invalid_input',
      field: 'arguments',
      constraint: 'Provide valid JSON arguments.',
    });
  }
}

const ackSchema = z.object({
  success: z.literal(true),
  data: z.object({
    acknowledged: z.tuple([
      z.object({ event_id: z.string(), phase: z.enum(['started', 'completion']) }),
    ]),
  }),
});

export function createAuditWriter(url: string, clientId: string, key: KeyObject): AuditWriter {
  const endpoint = new URL(url);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(endpoint.hostname);
  if (
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    !(endpoint.protocol === 'https:' || (loopback && endpoint.protocol === 'http:'))
  ) {
    throw new Error('Invalid audit endpoint');
  }
  return async (event, remaining) => {
    const body = JSON.stringify({ events: [event] });
    const bodySha256 = sha256(body);
    const attempts = event.phase === 'started' ? 1 : 3;
    for (let i = 0; i < attempts; i++) {
      if (remaining() < 1) break;
      try {
        const assertion = await clientAssertion({
          key,
          clientId,
          audience: endpoint.href,
          bodySha256,
        });
        const budget = remaining();
        if (budget < 1) break;
        const reply = await postAuditEnvelope(
          endpoint.href,
          body,
          assertion,
          Math.max(1, Math.floor(budget / (attempts - i)))
        );
        const ack = ackSchema.safeParse(reply);
        const record = ack.success ? ack.data.data.acknowledged[0] : undefined;
        if (record?.event_id === event.event_id && record.phase === event.phase) return;
      } catch {
        // Retry completion with identical bytes and a fresh assertion/JTI.
      }
    }
    throw new Error('Audit delivery unacknowledged');
  };
}
