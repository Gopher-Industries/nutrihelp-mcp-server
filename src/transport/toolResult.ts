import { ProtocolError, type CallToolResult } from '@modelcontextprotocol/server';
import { McpError, PROTOCOL_ERROR_CODES } from '../errors.ts';

/** Frame only declared errors. Unknown exceptions never leak credentials or upstream bodies. */
export async function frameToolResult(run: () => Promise<CallToolResult>): Promise<CallToolResult> {
  try {
    return await run();
  } catch (error) {
    if (!(error instanceof McpError)) {
      throw new ProtocolError(
        PROTOCOL_ERROR_CODES.upstream_failure,
        'The service is temporarily unavailable. Retry with the same confirmation.'
      );
    }
    const payload = error.toModel();
    if (error.class === 'invalid_input' || error.class === 'confirmation_required') {
      return {
        isError: error.class === 'invalid_input',
        content: [{ type: 'text', text: JSON.stringify(payload) }],
        // Confirmation is a declared tool response, so the SDK needs structured output
        // as well as text. Log-only mismatch details must stay out of both.
        ...(error.class === 'confirmation_required' ? { structuredContent: payload } : {}),
      };
    }
    throw new ProtocolError(PROTOCOL_ERROR_CODES[error.class], payload.message, payload);
  }
}
