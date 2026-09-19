import { describe, expect, it, vi } from 'vitest';
import type { AuthInfo, McpServer } from '@modelcontextprotocol/server';
import {
  createWriteAuthInfo,
  writeContextFor,
  assertMealWriteAuthorized,
} from '../../../src/auth/writeContext.ts';
import { registerTools } from '../../../src/tools/registry.ts';
import { activeGrant, mealConfig, verifiedContext } from '../../support/recordMeal.ts';
import { RESOURCE_METADATA_URL, SCOPES } from '../../support/testEnv.ts';

const claims = {
  sub: activeGrant.subject,
  client_id: activeGrant.clientId,
  grant_id: activeGrant.grantId,
  scope: SCOPES.meallogWrite,
  exp: Date.now() / 1000 + 300,
};
const request = {
  token: 'inbound',
  deadlineAt: Date.now() + 30000,
  correlationId: 'request-id',
  now: Date.now,
  resourceMetadataUrl: RESOURCE_METADATA_URL,
};

function registered(auth?: AuthInfo) {
  const registerTool = vi.fn();
  registerTools(
    { registerTool } as unknown as McpServer,
    { era: 'modern', ...(auth === undefined ? {} : { authInfo: auth }) },
    mealConfig
  );
  return registerTool.mock.calls.map(([name]) => name as string);
}

describe('trusted context for record_meal', () => {
  it('exposes the tool only from a matching validated token and live grant', () => {
    const auth = createWriteAuthInfo(claims, activeGrant, request);
    expect(writeContextFor(auth)).toMatchObject({
      userId: '7',
      assistantId: 'assistant-a',
      connectionId: 'connection-a',
    });
    expect(registered(auth)).toContain('record_meal');
  });

  it('ignores lookalike auth objects and copied SDK metadata', () => {
    const auth = createWriteAuthInfo(claims, activeGrant, request);
    if (!auth) throw new Error('Missing verified fixture');
    expect(registered({ ...auth, extra: { recordMeal: verifiedContext() } })).not.toContain(
      'record_meal'
    );
    expect(registered()).not.toContain('record_meal');
  });

  it.each([{ sub: 'other' }, { client_id: 'other' }, { grant_id: 'other' }])(
    'does not expose a write binding for mismatching or incomplete claims %j',
    (change) => {
      expect(createWriteAuthInfo({ ...claims, ...change }, activeGrant, request)).toBeUndefined();
    }
  );

  it('uses the intersection of signed and live scopes for tool discovery', () => {
    expect(
      registered(createWriteAuthInfo({ ...claims, scope: 'nutrition:read' }, activeGrant, request))
    ).not.toContain('record_meal');
    expect(
      registered(createWriteAuthInfo(claims, { ...activeGrant, scopes: [] }, request))
    ).not.toContain('record_meal');
  });

  it('requires an expiry in the verified token', () => {
    const incomplete = {
      sub: claims.sub,
      client_id: claims.client_id,
      grant_id: claims.grant_id,
      scope: claims.scope,
    };
    expect(createWriteAuthInfo(incomplete, activeGrant, request)).toBeUndefined();
  });

  it('rejects a token that expires while introspection is in flight', async () => {
    let time = 0;
    const context = verifiedContext({ now: () => time, expiresAt: 1, deadlineAt: 10000 });
    const checker = {
      assertGrantActive: vi.fn().mockImplementation(() => {
        time = 1001;
        return Promise.resolve(activeGrant);
      }),
    };
    await expect(assertMealWriteAuthorized(context, checker)).rejects.toMatchObject({
      class: 'unauthorized',
    });
  });

  it('refuses a spent budget after introspection', async () => {
    let time = 0;
    const context = verifiedContext({ now: () => time, deadlineAt: 500 });
    const checker = {
      assertGrantActive: vi.fn().mockImplementation(() => {
        time = 501;
        return Promise.resolve(activeGrant);
      }),
    };
    await expect(assertMealWriteAuthorized(context, checker)).rejects.toMatchObject({
      class: 'upstream_failure',
    });
  });
});
