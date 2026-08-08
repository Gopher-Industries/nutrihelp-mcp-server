import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // test/ mirrors src/ and is not colocated: the layers gate differently, and CI needs
    // `conformance` and `security` as separately named globs.
    include: ['test/**/*.test.ts'],

    // TEMPORARY. `test/unit`, `test/conformance` and `test/integration` are still empty, and
    // without this `npm test` and `npm run conformance` exit 1 so `validate` can never pass.
    // REMOVE PER LAYER AS EACH GAINS A SUITE: a green run over an empty glob is the same
    // fiction as the estate's `|| exit 0`, and one global flag hides it for every layer at once.
    passWithNoTests: true,

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
