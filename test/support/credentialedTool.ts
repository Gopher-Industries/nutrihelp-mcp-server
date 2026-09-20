/**
 * A tool whose backing endpoint is credentialed, for suites that need step 4 to be reachable.
 *
 * **Without this, every assertion about the credential step is vacuous.** The only tool on the
 * tree today is `nutrition_lookup`, whose backing endpoint is public, so it skips exchange
 * — so a suite proving "a revoked grant never reaches a cached credential" would be proving it
 * against a registry in which nothing could reach one. That reads exactly like a passing control.
 *
 * It is a **test descriptor, not a shipped tool**: it is handed to `registerTools` through
 * `RegistryConfig.extraTools`, it is absent from the frozen tool-to-scope map on purpose (so the
 * scope step gives it no requirement and the case is about the grant rather than about scope), and
 * it makes no outbound call of its own. It reports only **whether** a credential arrived, never
 * its value.
 */

import { z } from 'zod';
import type { ToolDescriptor, ToolRequest } from '../../src/tools/registry.ts';

/** Plain per the transport's routing-header grammar, so it can travel in `Mcp-Name`. */
export const CREDENTIALED_TOOL_NAME = 'credentialed_probe';

const inputSchema = z.object({});

const outputSchema = z.object({
  /** Whether step 4 produced a credential. The token itself is never returned. */
  credentialed: z.boolean(),
  /** The grant the credential was minted under, which is already a model-safe opaque reference. */
  grant_id: z.string(),
});

/**
 * Registered through `RegistryConfig.extraTools`. Typed loosely at the boundary for the same
 * reason the registry's own descriptor type is generic: the suite that injects it holds a
 * heterogeneous list.
 */
export const credentialedProbe = {
  name: CREDENTIALED_TOOL_NAME,
  contract: {
    title: 'Credentialed Probe',
    description: 'Test-only tool whose backing endpoint requires the exchanged credential.',
    outputSchema,
  },
  inputSchema,
  backing: 'credentialed',
  handler: (request: ToolRequest) => () => {
    const output = {
      credentialed: request.credential !== undefined,
      grant_id: request.credential?.grantId ?? '',
    };
    return {
      content: [{ type: 'text' as const, text: JSON.stringify(output) }],
      structuredContent: output,
    };
  },
} as const satisfies ToolDescriptor<typeof inputSchema>;

/**
 * The same probe with a **public** backing endpoint, so "step 4 is skipped and nothing else moves"
 * is a comparison between two instrumented tools rather than between one instrumented tool and the
 * real `nutrition_lookup`, whose handler this suite cannot see inside.
 */
export const PUBLIC_TOOL_NAME = 'public_probe';

export const publicProbe = {
  ...credentialedProbe,
  name: PUBLIC_TOOL_NAME,
  backing: 'public',
} as const satisfies ToolDescriptor<typeof inputSchema>;
