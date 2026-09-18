import { describe, expect, it, vi } from 'vitest';
import type { McpRequestContext, McpServer } from '@modelcontextprotocol/server';
import { registerTools } from '../../../src/tools/registry.ts';
import { inputSchema } from '../../../src/tools/nutritionLookup.ts';

describe('tool registry', () => {
  it('registers the nutrition lookup descriptor through the central dispatch path', () => {
    const registerTool = vi.fn();
    const server = { registerTool } as unknown as McpServer;

    registerTools(server, {} as McpRequestContext, {
      nutrihelpApiBaseUrl: 'https://api.nutrihelp.test',
      requestDeadlineMs: 30_000,
    });

    expect(registerTool).toHaveBeenCalledTimes(1);
    expect(registerTool).toHaveBeenCalledWith(
      'nutrition_lookup',
      expect.objectContaining({ inputSchema }),
      expect.any(Function)
    );
  });
});
