import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

// One egress door, not one HTTP door: a raw socket is the same hole with a different import.
const EGRESS_BUILTINS = ['http', 'https', 'net', 'tls', 'dgram', 'http2'];
const EGRESS_PACKAGES = ['undici', 'axios', 'node-fetch'];
const BANNED_ESTATE_MIDDLEWARE = ['express-rate-limit', 'cors'];

/** `paths` matches a specifier exactly, so `undici/index.js` slips past a ban on `undici`. */
function moduleForms(name, { builtin = false } = {}) {
  const forms = [name, `${name}/*`, `${name}/**`];
  if (builtin) forms.push(`node:${name}`, `node:${name}/*`, `node:${name}/**`);
  return forms;
}

const EGRESS_MODULE_GROUP = {
  group: [
    ...EGRESS_BUILTINS.flatMap((n) => moduleForms(n, { builtin: true })),
    ...EGRESS_PACKAGES.flatMap((n) => moduleForms(n)),
  ],
  message: 'Only src/upstream/client.ts may import an egress mechanism.',
};

const ESTATE_MIDDLEWARE_GROUP = {
  group: BANNED_ESTATE_MIDDLEWARE.flatMap((n) => moduleForms(n)),
  message: 'Estate middleware is not inherited.',
};

/** Separator must be `\x2F`: esquery ends its regex literal at the first bare `/`, which throws
 *  "Unterminated group" on every file. */
const SLASH = String.raw`\x2F`;
const EGRESS_DYNAMIC_RE =
  `^(node:)?(${EGRESS_BUILTINS.join('|')})(${SLASH}.*)?$` +
  `|^(${EGRESS_PACKAGES.join('|')})(${SLASH}.*)?$`;

/** `no-restricted-imports` misses dynamic `import()`; `no-restricted-globals` misses member
 *  access. Without these, `import('node:http')` and `globalThis.fetch` lint clean. */
const EGRESS_IMPORT_SYNTAX = [
  {
    selector: `ImportExpression[source.value=/${EGRESS_DYNAMIC_RE}/]`,
    message: 'Only src/upstream/client.ts may import an egress mechanism.',
  },
];

/** Split out because `test/**` is exempt from the import rules but not from this one. */
const EGRESS_FETCH_SYNTAX = [
  {
    selector: "MemberExpression[object.name='globalThis'][property.name='fetch']",
    message: 'Only src/upstream/client.ts may call out.',
  },
];

const EGRESS_SYNTAX = [...EGRESS_IMPORT_SYNTAX, ...EGRESS_FETCH_SYNTAX];

// Specifiers carry `.ts`: Node type-stripping runs the entrypoint directly.

const CHAIN_UPSTREAM = {
  group: ['**/upstream/client', '**/upstream/client.ts', '**/upstream/client.js'],
  message: 'Only src/auth/*, src/tools/* and src/audit/logger.ts may import the upstream client.',
};

const CHAIN_TOOL_MODULES = {
  group: ['**/tools/*', '!**/tools/registry', '!**/tools/registry.ts', '!**/tools/registry.js'],
  message: 'Only src/tools/registry.ts may import a tool module. It is the only dispatch path.',
};

/** A sibling import is written `./nutritionLookup.ts` and carries no `tools/` segment, so
 *  CHAIN_TOOL_MODULES cannot see it. Also blocks a shared helper there — deliberately. */
const CHAIN_TOOL_SIBLING = {
  group: ['./*'],
  message: 'A tool module imports no other tool module. Dispatch goes through the registry.',
};

const CHAIN_CONFIG = {
  group: ['**/config/index', '**/config/index.ts', '**/config/index.js'],
  message: 'Only src/server.ts may import src/config/index.ts. No config reads elsewhere.',
};

/** A `files:` override REPLACES a rule's options rather than merging them, so every zone
 *  restates the whole rule. Flags are `true` = permitted; `extra` appends restrictions. */
function restrictedImports(
  { upstreamClient = false, toolModules = false, config = false } = {},
  extra = []
) {
  const patterns = [EGRESS_MODULE_GROUP, ESTATE_MIDDLEWARE_GROUP];
  if (!upstreamClient) patterns.push(CHAIN_UPSTREAM);
  if (!toolModules) patterns.push(CHAIN_TOOL_MODULES);
  if (!config) patterns.push(CHAIN_CONFIG);
  return ['error', { patterns: [...patterns, ...extra] }];
}

export default tseslint.config(
  {
    // server.js is a 0-byte pre-v2 leftover; delete the file and this entry together.
    ignores: ['dist/**', 'node_modules/**', 'coverage/**', 'server.js'],
  },

  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,

  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      'no-restricted-globals': [
        'error',
        { name: 'fetch', message: 'Only src/upstream/client.ts may call out.' },
      ],
      'no-restricted-imports': restrictedImports(),
      'no-restricted-syntax': ['error', ...EGRESS_SYNTAX],

      'no-empty': ['error', { allowEmptyCatch: false }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },

  {
    files: ['src/upstream/client.ts'],
    rules: {
      'no-restricted-globals': 'off',
      'no-restricted-imports': 'off',
      'no-restricted-syntax': 'off',
    },
  },

  // Order matters: registry must follow the general tools rule.

  {
    files: ['src/auth/**', 'src/audit/logger.ts'],
    rules: { 'no-restricted-imports': restrictedImports({ upstreamClient: true }) },
  },

  {
    files: ['src/tools/**'],
    rules: {
      'no-restricted-imports': restrictedImports({ upstreamClient: true }, [CHAIN_TOOL_SIBLING]),
    },
  },

  {
    files: ['src/tools/registry.ts'],
    rules: {
      'no-restricted-imports': restrictedImports({ upstreamClient: true, toolModules: true }),
    },
  },

  {
    files: ['src/server.ts'],
    rules: { 'no-restricted-imports': restrictedImports({ config: true }) },
  },

  {
    // Imports are exempt so tests can use MockAgent. The call-out guard stays on: whether
    // test/integration/** may reach the network is a separate decision, not conceded here.
    files: ['test/**'],
    rules: {
      'no-restricted-imports': 'off',
      'no-restricted-syntax': ['error', ...EGRESS_FETCH_SYNTAX],
    },
  },

  {
    files: ['src/auth/**', 'src/tools/**'],
    rules: { complexity: ['error', 8] },
  },

  {
    files: ['src/tools/**'],
    rules: {
      // EGRESS_SYNTAX repeated because this override replaces the base rule's options.
      'no-restricted-syntax': [
        'error',
        ...EGRESS_SYNTAX,
        {
          selector: "CallExpression[callee.property.name='describe'] > TemplateLiteral",
          message: 'Tool descriptions are string literals. No interpolation.',
        },
        {
          selector: "CallExpression[callee.property.name='describe'] > BinaryExpression",
          message: 'Tool descriptions are string literals. No concatenation.',
        },
      ],
    },
  },

  {
    files: ['scripts/**', 'eslint.config.js', 'vitest.config.ts'],
    rules: {
      'no-restricted-imports': 'off',
      'no-restricted-globals': 'off',
      'no-restricted-syntax': 'off',
    },
  },

  {
    // Outside the TypeScript project, so typed rules have no type information here.
    files: ['eslint.config.js'],
    extends: [tseslint.configs.disableTypeChecked],
  }
);
