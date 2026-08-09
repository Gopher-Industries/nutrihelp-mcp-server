import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // test/ mirrors src/ and is not colocated: the layers gate differently, and CI needs
    // `conformance` and `security` as separately named globs.
    include: ['test/**/*.test.ts'],

    // `passWithNoTests` is deliberately NOT set here. Globally it made `npm test` and
    // `npm run conformance` exit 0 over globs with no files, so `validate` and the pre-push hook
    // asserted nothing — the same fiction as the estate's `|| exit 0`. It now lives
    // on the individual scripts for the layers that have no suite yet, so each drops it alone.

    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**'],
      // Branch only, and only here. No floor elsewhere; line coverage is measured, not gated.
      thresholds: {
        'src/auth/**': { branches: 90 },
        'src/tools/**': { branches: 90 },
      },
    },
  },
});
