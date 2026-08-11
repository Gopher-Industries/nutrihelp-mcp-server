import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

/* ONE EGRESS DOOR — DEFENCE IN DEPTH, NOT THE BOUNDARY. The boundary is architectural: one module
 * makes outbound calls, and that is held by the upstream design and by review. These selectors
 * were recorded "verified" after walking only some of the axes five times running, so read the
 * list below as state, not as a closure claim. The control is the frozen case table in
 * test/security/egress.test.ts, plus the banned-module list, plus review.
 *
 *   1. MODULE SPECIFIER   bare / node:-prefixed / subpath / static / dynamic, plus non-literal
 *                         and computed dynamic specifiers, which a `source.value` test cannot see
 *   2. REFERENCE FORM     bare identifier, dot, computed, alias, destructure, destructure-renamed
 *   3. RECEIVER           `globalThis` and `global`. NOT `self`: tsc rejects it under
 *                         `"lib": ["ES2023"]` with no DOM — adding DOM types makes it live and
 *                         it must join EGRESS_RECEIVERS in that same change
 *   4. GUARDED IDENTIFIER `fetch` is not the only global that opens a socket. `WebSocket` needs
 *                         no import at all. Adding an egress primitive here is a security change
 *   5. RESOLVER           who hands the capability back, which axes 1-4 never ask:
 *                         `process.getBuiltinModule`, `eval`, `Function`
 *
 * Axis 3 is UNBOUNDED and no selector list closes it. What is matched is the declarator, cast,
 * assignment and parameter-default productions, and nothing else: `Reflect.get`, object and array
 * literal capture, function return and `PropertyDefinition` all still reach the object. Out of
 * scope by decision — do not chase them with more selectors.
 */
const EGRESS_BUILTINS = [
  'http',
  'https',
  'net',
  'tls',
  'dgram',
  'http2',
  // Not HTTP, but each reaches the network or hands back something that does.
  'child_process',
  'module',
  'dns',
  'worker_threads',
  'vm',
  'cluster',
  'repl',
  'inspector',
  'process',
];
const EGRESS_PACKAGES = ['undici', 'axios', 'node-fetch'];
/** Globals that open an outbound connection with no import. Adding one is a security change. */
const EGRESS_GLOBALS = ['fetch', 'WebSocket', 'EventSource'];
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

/** `scripts/**` and `test/**` are exempt from every egress rule, so importing either from `src/**`
 *  launders the exemption into a guarded module. When a zone is exempted, ban the guarded zones
 *  from importing it in the same change. */
const EXEMPT_ZONES = {
  group: ['**/scripts/*', '**/scripts/**', '**/test/*', '**/test/**'],
  message:
    'src/** may not import scripts/** or test/**. Both are exempt from the egress rules, so importing one launders the exemption into a guarded module. Shared code belongs in src/.',
};

/** Separator must be `\x2F`: esquery ends its regex literal at the first bare `/`, which throws
 *  "Unterminated group" on every file. */
const SLASH = String.raw`\x2F`;

/** Selectors that are NOT part of the egress group, so the one egress door inherits them too.
 *  It is exempt from calling out, not from laundering an exemption or building code from a
 *  string. Any zone that overrides `no-restricted-syntax` must restate these. */
const NON_EGRESS_SYNTAX = [
  {
    // `no-restricted-imports` never sees a dynamic import, so EXEMPT_ZONES needs a counterpart.
    selector: `ImportExpression[source.value=/(^|${SLASH})(scripts|test)${SLASH}/]`,
    message:
      'src/** may not import scripts/** or test/**, dynamically either. Both are exempt from the egress rules, so importing one launders the exemption.',
  },
  {
    // `no-new-func` only fires where the `Function` global is directly the callee, so the alias
    // walks past it — and an alias is exactly what gets reached for once the direct form errors.
    selector: 'VariableDeclarator[init.name=/^(Function|eval)$/]',
    message:
      'Aliasing `Function` or `eval` is not a way around no-new-func and no-eval. Nothing here builds code from a string.',
  },
];

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
  {
    // A `source.value` test only sees a Literal. `const s = 'node:http'; import(s)` and
    // `import('node:' + 'http')` have no `value` to match, so they walked straight past the
    // selector above. An unanalysable specifier is refused outright rather than waved through.
    selector: "ImportExpression[source.type!='Literal']",
    message:
      'Dynamic import with a non-literal specifier cannot be checked against the egress list, so it is refused. Use a literal.',
  },
];

/** Split out because `test/**` is exempt from the import rules but not from this one.
 *
 *  This covers axes 2, 3 and 4 from the header. It is NOT an exhaustive list of ways to reach the
 *  global object — see the header on axis 3 being unbounded. Matching is by identifier NAME, not
 *  by binding, so a local named `global` is flagged too; the message says so, and a one-line
 *  disable with a reason is the intended escape. */
const EGRESS_RECEIVERS = String.raw`/^(globalThis|global)$/`;
const EGRESS_GLOBAL_PROPS = `/^(${EGRESS_GLOBALS.join('|')})$/`;
const RECEIVER_NOTE = 'an identifier named `globalThis` or `global`';

const EGRESS_FETCH_SYNTAX = [
  {
    selector: `MemberExpression[object.name=${EGRESS_RECEIVERS}][property.name=${EGRESS_GLOBAL_PROPS}]`,
    message: `Only src/upstream/client.ts may call out. This reads an egress global off ${RECEIVER_NOTE}.`,
  },
  {
    selector: `MemberExpression[object.name=${EGRESS_RECEIVERS}][computed=true]`,
    message: `Only src/upstream/client.ts may call out. Computed access to ${RECEIVER_NOTE} is not a way around it.`,
  },
  // Axis 3, the cheap high-traffic productions. Each is a DIFFERENT node type, which is why one
  // selector cannot cover them. `TSAsExpression` is listed first because it is the one the rule
  // itself provokes: once `const g = globalThis` errors, a cast is what gets reached for next.
  {
    selector: `VariableDeclarator[init.name=${EGRESS_RECEIVERS}]`,
    message: `Only src/upstream/client.ts may call out. Aliasing or destructuring ${RECEIVER_NOTE} is not a way around it.`,
  },
  {
    selector: `VariableDeclarator[init.type='TSAsExpression'][init.expression.name=${EGRESS_RECEIVERS}]`,
    message: `Only src/upstream/client.ts may call out. Casting ${RECEIVER_NOTE} does not change what it is.`,
  },
  {
    selector: `AssignmentExpression[right.name=${EGRESS_RECEIVERS}]`,
    message: `Only src/upstream/client.ts may call out. Assigning ${RECEIVER_NOTE} is not a way around it.`,
  },
  {
    selector: `AssignmentPattern[right.name=${EGRESS_RECEIVERS}]`,
    message: `Only src/upstream/client.ts may call out. Defaulting a parameter to ${RECEIVER_NOTE} is not a way around it.`,
  },
];

/** Axis 5. In the egress group, so the door is exempt for the same reason it may import a
 *  builtin. The other two resolvers, `eval` and `Function`, are not: see NON_EGRESS_SYNTAX. */
const EGRESS_RESOLVER_SYNTAX = [
  {
    selector: "MemberExpression[object.name='process'][property.name='getBuiltinModule']",
    message:
      'Only src/upstream/client.ts may call out. `process.getBuiltinModule` hands back the module registry, which resolves every banned module.',
  },
  {
    selector: "MemberExpression[object.name='process'][computed=true]",
    message:
      'Only src/upstream/client.ts may call out. Computed access to `process` is not a way around the resolver ban.',
  },
];

const EGRESS_SYNTAX = [
  ...EGRESS_IMPORT_SYNTAX,
  ...EGRESS_FETCH_SYNTAX,
  ...EGRESS_RESOLVER_SYNTAX,
  ...NON_EGRESS_SYNTAX,
];

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
  { egress = false, upstreamClient = false, toolModules = false, config = false } = {},
  extra = []
) {
  // EXEMPT_ZONES has no flag: a flag would be a switch for turning the laundering path back on.
  const patterns = [ESTATE_MIDDLEWARE_GROUP, EXEMPT_ZONES];
  if (!egress) patterns.push(EGRESS_MODULE_GROUP);
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
      // Axis 4. `WebSocket` opens an outbound socket with NO import, so the module bans never
      // see it and a guard naming only `fetch` is a guard on the wrong noun.
      'no-restricted-globals': [
        'error',
        ...EGRESS_GLOBALS.map((name) => ({
          name,
          message: `Only src/upstream/client.ts may call out. \`${name}\` opens an outbound connection with no import.`,
        })),
      ],
      'no-restricted-imports': restrictedImports(),
      'no-restricted-syntax': ['error', ...EGRESS_SYNTAX],

      // The other two axis-5 resolvers. Unscoped: nothing here builds code from a string.
      'no-eval': 'error',
      'no-new-func': 'error',

      'no-empty': ['error', { allowEmptyCatch: false }],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
    },
  },

  {
    // The one egress door. Its exemption is COMPOSED, not switched off: `'off'` would also drop
    // the import-chain groups it was never meant to escape, leaving the single module allowed to
    // call out as the single module free to import a tool or read config directly. Only the
    // egress restrictions are lifted here; the chain and estate-middleware bans stay on.
    files: ['src/upstream/client.ts'],
    rules: {
      'no-restricted-globals': 'off',
      // `upstreamClient` is deliberately NOT set: CHAIN_UPSTREAM only ever meant "do not import
      // some other upstream client", and exempting the highest-value module from it buys nothing.
      'no-restricted-imports': restrictedImports({ egress: true }),
      // `['error', ...selectors]` replaces the options; a bare `['error']` RETAINS them, which
      // once left all four egress selectors in force on this very module.
      'no-restricted-syntax': ['error', ...NON_EGRESS_SYNTAX],
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
    // `scripts/**/*.mjs` is plain JS on purpose — the Node version guard has to run and print a
    // useful message on the very versions that cannot type-strip a `.ts` file.
    files: ['eslint.config.js', 'scripts/**/*.mjs'],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: {
      // Declared explicitly rather than pulled from a `globals` preset: these are the only three
      // the guard uses, and a narrow list keeps `no-undef` meaningful here. Deliberately NOT set
      // for `src/**` or `test/**` — leaving egress globals undeclared there is what lets
      // `no-restricted-globals` fire on the name regardless of what the runtime provides.
      globals: { console: 'readonly', process: 'readonly', URL: 'readonly' },
    },
  }
);
