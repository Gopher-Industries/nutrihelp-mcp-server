/**
 * Five-class error taxonomy. Exhaustive `never` switch so a sixth class fails the build.
 *
 * `toModel()` and `toLog()` return separate objects: one serialised twice would make the split
 * decorative. This module imports nothing and knows nothing about HTTP; transport frames status
 * and `WWW-Authenticate` from `class`.
 */

export const MCP_ERROR_CLASSES = [
  'unauthorized',
  'insufficient_scope',
  'invalid_input',
  'upstream_failure',
  'confirmation_required',
] as const;

export type McpErrorClass = (typeof MCP_ERROR_CLASSES)[number];

/** Returned to the model as a tool result, not a protocol failure. */
type ModelFacingErrorClass = Extract<McpErrorClass, 'invalid_input' | 'confirmation_required'>;

/**
 * Classes reported as a JSON-RPC error (no tool result). Written as a subtraction so a sixth
 * class lands here until someone decides which side it belongs on.
 *
 * `confirmation_required` is thrown internally; on the wire it is a successful pending-action
 * result, same as `invalid_input`.
 */
export type ProtocolErrorClass = Exclude<McpErrorClass, ModelFacingErrorClass>;

/**
 * Application codes in -32000..-32019. Skip -32001/-32002 (SDK). Never reuse retired -32005.
 * Values are `number` so callers do not pin a literal; keys are exact so a class add/remove fails here.
 */
export const PROTOCOL_ERROR_CODES: Readonly<Record<ProtocolErrorClass, number>> = {
  unauthorized: -32000,
  insufficient_scope: -32003,
  upstream_failure: -32004,
};

/** Static literals. A mapped record so a sixth class fails the build here too. */
const MODEL_MESSAGES = {
  unauthorized: 'Authentication is required, or the credential presented was not accepted.',
  insufficient_scope: 'The granted scopes do not cover this operation.',
  invalid_input: 'One or more arguments did not satisfy the declared schema.',
  upstream_failure: 'The service is temporarily unavailable. The request can be retried.',
  confirmation_required: 'This action needs the user to confirm it before it can run.',
} as const satisfies Readonly<Record<McpErrorClass, string>>;

/* One init per class. No body, stack, status, or details bag — extras are stripped. */

export interface UnauthorizedInit {
  readonly class: 'unauthorized';
  /** Log side only. */
  readonly reason: string;
  readonly resourceMetadataUrl: string;
}

export interface InsufficientScopeInit {
  readonly class: 'insufficient_scope';
  /** Named to the model for step-up. */
  readonly requiredScope: string;
  /** Log side only. */
  readonly heldScopes: readonly string[];
  readonly resourceMetadataUrl: string;
  readonly userId: string;
  readonly clientId: string;
  /** Opaque grant reference, never the token. */
  readonly grantId: string;
  readonly operation: string;
}

export interface InvalidInputInit {
  readonly class: 'invalid_input';
  readonly field: string;
  readonly constraint: string;
}

export interface UpstreamFailureInit {
  readonly class: 'upstream_failure';
  /** Family such as `5xx` or `timeout`; never a status code; log-only. */
  readonly statusClass: string;
  /** Log-only stable identifier. */
  readonly errorCode: string;
  /** Endpoint class, never the path. */
  readonly endpointClass: string;
  readonly correlationId: string;
  readonly latencyMs: number;
}

export interface ConfirmationRequiredInit {
  readonly class: 'confirmation_required';
  /** Server-side wording of the resolved arguments. */
  readonly summary: string;
  /** Same name as the input argument so it round-trips untransformed. */
  readonly confirmation_token: string;
  /** Omitted when absent or empty; never present as `[]`. */
  readonly unresolved_items?: readonly string[];
}

export type McpErrorInit =
  | UnauthorizedInit
  | InsufficientScopeInit
  | InvalidInputInit
  | UpstreamFailureInit
  | ConfirmationRequiredInit;

/** Assistant-facing. Generic wherever detail helps an attacker more than a client. */
export type McpErrorModelPayload =
  | {
      readonly class: 'unauthorized';
      readonly message: string;
      readonly resourceMetadataUrl: string;
    }
  | {
      readonly class: 'insufficient_scope';
      readonly message: string;
      /** Challenge error identifier. Transport frames it; this module names it. */
      readonly error: 'insufficient_scope';
      readonly requiredScope: string;
      readonly resourceMetadataUrl: string;
    }
  | {
      readonly class: 'invalid_input';
      readonly message: string;
      readonly field: string;
      readonly constraint: string;
    }
  | {
      readonly class: 'upstream_failure';
      readonly message: string;
      readonly retryable: true;
    }
  | {
      readonly class: 'confirmation_required';
      readonly message: string;
      readonly summary: string;
      readonly confirmation_token: string;
      readonly unresolved_items?: readonly string[];
    };

/** Operator-facing. No body, stack, or raw argument. */
export type McpErrorLogPayload =
  | {
      readonly class: 'unauthorized';
      readonly reason: string;
      readonly resourceMetadataUrl: string;
    }
  | {
      readonly class: 'insufficient_scope';
      readonly requiredScope: string;
      readonly heldScopes: readonly string[];
      readonly userId: string;
      readonly clientId: string;
      readonly grantId: string;
      readonly operation: string;
    }
  | {
      readonly class: 'invalid_input';
      readonly field: string;
      readonly constraint: string;
    }
  | {
      readonly class: 'upstream_failure';
      readonly statusClass: string;
      readonly errorCode: string;
      readonly endpointClass: string;
      readonly correlationId: string;
      readonly latencyMs: number;
    }
  | {
      readonly class: 'confirmation_required';
      readonly summary: string;
      readonly confirmation_token: string;
    };

/** Omit the key when items are absent or empty. Copy the array so no caller reference escapes. */
function renderUnresolvedItems(items: readonly string[] | undefined): {
  unresolved_items?: readonly string[];
} {
  return items === undefined || items.length === 0 ? {} : { unresolved_items: [...items] };
}

/** Copy declared fields only. A sixth class or a cast-in extra throws rather than leaking later. */
function declaredFieldsOnly(init: McpErrorInit): McpErrorInit {
  switch (init.class) {
    case 'unauthorized':
      return {
        class: 'unauthorized',
        reason: init.reason,
        resourceMetadataUrl: init.resourceMetadataUrl,
      };
    case 'insufficient_scope':
      return {
        class: 'insufficient_scope',
        requiredScope: init.requiredScope,
        heldScopes: [...init.heldScopes],
        resourceMetadataUrl: init.resourceMetadataUrl,
        userId: init.userId,
        clientId: init.clientId,
        grantId: init.grantId,
        operation: init.operation,
      };
    case 'invalid_input':
      return { class: 'invalid_input', field: init.field, constraint: init.constraint };
    case 'upstream_failure':
      return {
        class: 'upstream_failure',
        statusClass: init.statusClass,
        errorCode: init.errorCode,
        endpointClass: init.endpointClass,
        correlationId: init.correlationId,
        latencyMs: init.latencyMs,
      };
    case 'confirmation_required':
      return {
        class: 'confirmation_required',
        summary: init.summary,
        confirmation_token: init.confirmation_token,
        ...renderUnresolvedItems(init.unresolved_items),
      };
    default: {
      const unreachable: never = init;
      throw new TypeError(`McpError: undeclared error class ${String(unreachable)}`);
    }
  }
}

/**
 * The one error type thrown across this server. Constructed at the throw site with everything the
 * log needs; the transport boundary is the only caller of `toModel()`.
 */
export class McpError extends Error {
  readonly class: McpErrorClass;

  /** Private and rebuilt from declared fields, so the raw init is neither retained nor reachable. */
  readonly #init: McpErrorInit;

  constructor(init: McpErrorInit) {
    // Rebuild before super(). The caller's object is read once: a getter can change on a second
    // read, and `class` selects the message. A refused init never produces a half-built Error.
    const declared = declaredFieldsOnly(init);
    super(MODEL_MESSAGES[declared.class]);
    this.name = 'McpError';
    this.#init = declared;
    this.class = this.#init.class;
  }

  /** A fresh object every call. Never the log payload, and never a view onto it. */
  toModel(): McpErrorModelPayload {
    const init = this.#init;
    switch (init.class) {
      case 'unauthorized':
        return {
          class: 'unauthorized',
          message: MODEL_MESSAGES.unauthorized,
          resourceMetadataUrl: init.resourceMetadataUrl,
        };
      case 'insufficient_scope':
        return {
          class: 'insufficient_scope',
          message: MODEL_MESSAGES.insufficient_scope,
          error: 'insufficient_scope',
          requiredScope: init.requiredScope,
          resourceMetadataUrl: init.resourceMetadataUrl,
        };
      case 'invalid_input':
        return {
          class: 'invalid_input',
          message: MODEL_MESSAGES.invalid_input,
          field: init.field,
          constraint: init.constraint,
        };
      case 'upstream_failure':
        return {
          class: 'upstream_failure',
          message: MODEL_MESSAGES.upstream_failure,
          retryable: true,
        };
      case 'confirmation_required':
        return {
          class: 'confirmation_required',
          message: MODEL_MESSAGES.confirmation_required,
          summary: init.summary,
          confirmation_token: init.confirmation_token,
          ...renderUnresolvedItems(init.unresolved_items),
        };
      default: {
        const unreachable: never = init;
        return unreachable;
      }
    }
  }

  /** A fresh object every call, and a different one from `toModel()`. */
  toLog(): McpErrorLogPayload {
    const init = this.#init;
    switch (init.class) {
      case 'unauthorized':
        return {
          class: 'unauthorized',
          reason: init.reason,
          resourceMetadataUrl: init.resourceMetadataUrl,
        };
      case 'insufficient_scope':
        return {
          class: 'insufficient_scope',
          requiredScope: init.requiredScope,
          heldScopes: [...init.heldScopes],
          userId: init.userId,
          clientId: init.clientId,
          grantId: init.grantId,
          operation: init.operation,
        };
      case 'invalid_input':
        return { class: 'invalid_input', field: init.field, constraint: init.constraint };
      case 'upstream_failure':
        return {
          class: 'upstream_failure',
          statusClass: init.statusClass,
          errorCode: init.errorCode,
          endpointClass: init.endpointClass,
          correlationId: init.correlationId,
          latencyMs: init.latencyMs,
        };
      case 'confirmation_required':
        return {
          class: 'confirmation_required',
          summary: init.summary,
          confirmation_token: init.confirmation_token,
        };
      default: {
        const unreachable: never = init;
        return unreachable;
      }
    }
  }
}
