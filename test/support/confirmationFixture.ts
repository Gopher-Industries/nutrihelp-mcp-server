import type { ConfirmationStore } from '../../src/consent/confirmation.ts';
import { ConfirmationError } from '../../src/errors.ts';

/** Non-write suites must fail closed if they unexpectedly reach confirmation storage. */
export const unavailableConfirmations: ConfirmationStore = {
  issue: () => Promise.reject(new ConfirmationError('confirmation_store_unavailable')),
  execute: () => Promise.reject(new ConfirmationError('confirmation_store_unavailable')),
};
