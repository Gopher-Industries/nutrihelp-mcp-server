import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // test/ mirrors src/ and is not colocated: the layers gate differently, and CI needs
    // `conformance` and `security` as separately named globs.
    include: ['test/**/*.test.ts'],

    // Every test layer now has a suite; an empty glob must fail. Redis integration tests
    // explicitly report a skip only when their connection URL is absent. CI supplies Redis.

    coverage: {
      provider: 'v8',
      // Guarded by coverageThresholds.test.ts. CLI `--coverage.reporter` REPLACES this array.
      reporter: ['text', 'lcov', 'json-summary'],
      // Without this, red-by-design cases mean no report is written and thresholds never evaluate.
      reportOnFailure: true,
      include: ['src/**'],
      // Branch only, and only here. Evaluated by `npm run coverage:auth` after a green in-scope
      // suite; wiring guards live in test/unit/coverageThresholds.test.ts.
      thresholds: {
        'src/auth/**': { branches: 90 },
        'src/consent/**': { branches: 90 },
        'src/tools/**': { branches: 90 },
      },
    },
  },
});
