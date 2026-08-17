/**
 * Environment loading and startup validation.
 * Partial: only the variables needed to boot the transport.
 */

export interface ServerConfig {
  readonly port: number;
  /** Hostnames only — the guard is port-agnostic. */
  readonly allowedOriginHostnames: readonly string[];
  readonly nutrihelpApiUrl: string;
}

function originToHostname(origin: string): string {
  try {
    const hostname = new URL(origin).hostname;
    if (hostname === '') {
      throw new Error('empty hostname');
    }
    return hostname;
  } catch {
    throw new Error(`MCP_ALLOWED_ORIGINS entry is not a valid URL: ${origin}`);
  }
}

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function validatedUrl(name: string, value: string): string {
  try {
    new URL(value);
    return value;
  } catch {
    throw new Error(`${name} is not a valid URL: ${value}`);
  }
}

export function loadConfig(): ServerConfig {
  const rawPort = required('PORT');
  const port = Number.parseInt(rawPort, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`PORT must be an integer between 1 and 65535, received: ${rawPort}`);
  }

  const allowedOrigins = required('MCP_ALLOWED_ORIGINS')
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  if (allowedOrigins.length === 0) {
    throw new Error('MCP_ALLOWED_ORIGINS must list at least one origin');
  }

  const allowedOriginHostnames = [
    ...new Set(allowedOrigins.map((origin) => originToHostname(origin))),
  ];

  const nutrihelpApiUrl = validatedUrl('NUTRIHELP_API_URL', required('NUTRIHELP_API_URL'));

  return { port, allowedOriginHostnames, nutrihelpApiUrl };
}
