import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // test/ mirrors src/ and is not colocated: the layers gate differently, and CI needs
    // `conformance` and `security` as separately named globs.
    include: ['test/**/*.test.ts'],

    // `passWithNoTests` is deliberately NOT set here. Globally it made `npm test` and
    // `npm run conformance` exit 0 over globs with no files, so `validate` and the pre-push hook
    // asserted nothing — the same fiction as the estate's `|| exit 0`. It now lives on the
    // individual npm script for the one layer that still has no suite, `test:integration`, which
    // cannot run anywhere until a reachable backend and a seeded account exist. Every other
    // layer exits 1 on an empty glob, verified by running rather than by reading.

    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**'],
      // Branch only, and only here. Evaluated by `npm run coverage:auth` after a green in-scope
      // suite; wiring guards live in test/unit/coverageThresholds.test.ts.
      thresholds: {
        'src/auth/**': { branches: 90 },
        'src/tools/**': { branches: 90 },
      },
    },
  },
});
