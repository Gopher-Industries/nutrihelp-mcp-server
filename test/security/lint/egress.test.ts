/**
 * Security suite: the one-egress-door lint rule, driven as a control instead of read as one.
 *
 * This rule has been recorded "verified" four times and been bypassable after each one, because
 * every verification was a throwaway manual probe that rotted the moment the config changed.
 * This file is the standing replacement. A bypass is now a red test, not a discovery.
 *
 * UNLIKE THE REST OF test/security/**, THIS SUITE IS GREEN. The other files there are red by
 * design pending modules that do not exist. This one tests configuration that exists today, so a
 * red row here is a live gap in a security control and must be reported, never skipped.
 *
 * HOW IT WORKS: snippets are linted through the ESLint Node API with a `filePath` that selects
 * the config zone. `lintText` never reads that path, so the same snippet can be asserted blocked
 * under `src/auth/` and permitted under `src/upstream/client.ts` with nothing on disk. Snippets
 * are strings for the same reason, and because a snippet written as real code would be linted as
 * part of this file and trip the very rule under test.
 *
 * DO NOT make these paths real. `src/upstream/client.ts` in particular is asserted absent by
 * test/security/upstream/client.test.ts.
 *
 * BOTH KINDS OF ROW ARE LOAD-BEARING. Expected-blocked rows alone are satisfied by a config that
 * rejects everything; expected-clean rows alone are satisfied by a harness that lints nothing. A
 * probe run during review reported every case clean because the ESLint call had errored without
 * linting, which is why `expectNoFatal` runs on every row and the harness self-check runs first.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import type { Linter } from 'eslint';
import tseslint from 'typescript-eslint';
import { beforeAll, describe, expect, it } from 'vitest';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

/**
 * Zone selectors. None of these files needs to exist, and none of them does today.
 * `src/upstream/client.ts` must stay that way.
 */
const ZONE = {
  auth: 'src/auth/tokenValidator.ts',
  tools: 'src/tools/getMealPlan.ts',
  door: 'src/upstream/client.ts',
  tests: 'test/unit/example.test.ts',
} as const;

/**
 * The three rules that carry the egress control. A blocked row names one of these specifically:
 * asserting "some error" would be satisfied by a parse failure or an unrelated type-aware rule,
 * which is how a suite goes green while the control is off.
 */
const EGRESS_RULE_IDS = [
  'no-restricted-globals',
  'no-restricted-syntax',
  'no-restricted-imports',
] as const;
type EgressRuleId = (typeof EGRESS_RULE_IDS)[number];

const isEgressRuleId = (id: string | null): id is EgressRuleId =>
  id !== null && (EGRESS_RULE_IDS as readonly string[]).includes(id);

/**
 * The repository config pins `projectService: true` and the type-checked presets, and the type
 * service refuses any path that is not on disk — every snippet comes back as a fatal parse error
 * and no rule ever runs. Type information is switched off here so the parser accepts a synthetic
 * path. This is sound because all three rules under test are pure-AST rules that never consult a
 * type, and the `harness self-check` block below proves the override left them at error severity.
 */
const HARNESS_OVERRIDE = [
  tseslint.configs.disableTypeChecked,
  { languageOptions: { parserOptions: { projectService: false, project: false } } },
] as unknown as Linter.Config[];

let eslint: ESLint;

beforeAll(() => {
  eslint = new ESLint({ cwd: REPO_ROOT, overrideConfig: HARNESS_OVERRIDE });
});

interface LintOutcome {
  readonly egress: EgressRuleId[];
  readonly fatal: Linter.LintMessage[];
}

async function lintSnippet(source: string, zone: string): Promise<LintOutcome> {
  const results = await eslint.lintText(source, {
    filePath: path.join(REPO_ROOT, zone),
    warnIgnored: false,
  });
  const result = results[0];
  if (!result) {
    throw new Error(
      `Linting produced no result for ${zone}. The snippet was never inspected, so every ` +
        `assertion about it would be vacuous.`
    );
  }
  return {
    egress: result.messages.map((m) => m.ruleId).filter(isEgressRuleId),
    fatal: result.messages.filter((m) => m.fatal === true),
  };
}

/**
 * The anti-vacuity guard, run on every row of both kinds. A fatal message means the snippet never
 * parsed, so no rule could have fired and a clean result proves nothing.
 */
function expectNoFatal(outcome: LintOutcome, zone: string): void {
  expect(
    outcome.fatal.map((m) => m.message),
    `The snippet failed to parse under ${zone}, so no rule could run and this row asserts ` +
      `nothing. Fix the harness before trusting any result in this file.`
  ).toEqual([]);
}

interface BlockedRow {
  readonly name: string;
  readonly code: string;
  readonly zone: string;
  readonly rule: EgressRuleId;
}

interface CleanRow {
  readonly name: string;
  readonly code: string;
  readonly zone: string;
}

async function expectBlocked({ code, zone, rule }: BlockedRow): Promise<void> {
  const outcome = await lintSnippet(code, zone);
  expectNoFatal(outcome, zone);
  expect(
    outcome.egress,
    `This reaches the network from ${zone} and lint let it through. That is a live egress ` +
      `bypass: close it in eslint.config.js, and do not relax this row.`
  ).toContain(rule);
}

async function expectClean({ code, zone }: CleanRow): Promise<void> {
  const outcome = await lintSnippet(code, zone);
  expectNoFatal(outcome, zone);
  expect(
    outcome.egress,
    `An egress rule fired in ${zone}, where this code is permitted. The rule now refuses ` +
      `legitimate code, which is how a control gets switched off wholesale to unblock someone.`
  ).toEqual([]);
}

/**
 * Row builders. Passing the rows through a typed parameter keeps each rule name checked against
 * the union instead of widening to `string`, so a typo in a rule id is a compile error rather
 * than a row that can never match.
 */
const blockedBy = (
  zone: string,
  rule: EgressRuleId,
  rows: readonly Omit<BlockedRow, 'zone' | 'rule'>[]
): BlockedRow[] => rows.map((row) => ({ ...row, zone, rule }));

const blocked = (zone: string, rows: readonly Omit<BlockedRow, 'zone'>[]): BlockedRow[] =>
  rows.map((row) => ({ ...row, zone }));

const clean = (zone: string, rows: readonly Omit<CleanRow, 'zone'>[]): CleanRow[] =>
  rows.map((row) => ({ ...row, zone }));

/* ------------------------------------------------------------------------------------------ */

describe('harness self-check', () => {
  it('reports a known-bad snippet as blocked', async () => {
    const outcome = await lintSnippet(`export const r = await fetch('https://x');\n`, ZONE.auth);
    expectNoFatal(outcome, ZONE.auth);
    expect(
      outcome.egress,
      'The positive control came back clean. Every clean row in this file is therefore ' +
        'meaningless: the harness is not linting.'
    ).toContain('no-restricted-globals');
  });

  it('reports a known-good snippet as clean', async () => {
    const outcome = await lintSnippet(`export const x = { a: 1 };\n`, ZONE.auth);
    expectNoFatal(outcome, ZONE.auth);
    expect(
      outcome.egress,
      'The negative control came back blocked. Every blocked row in this file is therefore ' +
        'meaningless: the config would reject anything.'
    ).toEqual([]);
  });

  it('leaves all three egress rules at error severity despite the type-checking override', async () => {
    // Typed at the boundary: `calculateConfigForFile` is declared as returning `any`.
    const config = (await eslint.calculateConfigForFile(path.join(REPO_ROOT, ZONE.auth))) as {
      readonly rules?: Readonly<Record<string, unknown>>;
    };
    for (const ruleId of EGRESS_RULE_IDS) {
      const entry = config.rules?.[ruleId];
      expect(
        Array.isArray(entry) ? entry[0] : entry,
        `${ruleId} is not at error severity in the harness config. The override that disables ` +
          `type-aware linting has disabled a rule under test, so this suite proves nothing.`
      ).toBe(2);
    }
  });
});

/* --- Axis 1: module specifier ---------------------------------------------------------------
 * Bare, node:-prefixed, subpath, static, dynamic, and the two non-literal dynamic forms that a
 * `source.value` selector cannot see. */

const AXIS_1_MODULE_SPECIFIER: BlockedRow[] = blockedBy(ZONE.auth, 'no-restricted-imports', [
  { name: "import 'node:http'", code: `import http from 'node:http';\nexport const x = http;\n` },
  { name: "import 'http'", code: `import http from 'http';\nexport const x = http;\n` },
  { name: "import 'node:https'", code: `import h from 'node:https';\nexport const x = h;\n` },
  { name: "import 'node:net'", code: `import net from 'node:net';\nexport const x = net;\n` },
  { name: "import 'node:tls'", code: `import tls from 'node:tls';\nexport const x = tls;\n` },
  { name: "import 'node:dgram'", code: `import d from 'node:dgram';\nexport const x = d;\n` },
  { name: "import 'node:http2'", code: `import h from 'node:http2';\nexport const x = h;\n` },
  { name: "import 'node:dns'", code: `import dns from 'node:dns';\nexport const x = dns;\n` },
  {
    name: "import 'node:worker_threads'",
    code: `import w from 'node:worker_threads';\nexport const x = w;\n`,
  },
  {
    name: "import 'child_process'",
    code: `import { exec } from 'child_process';\nexport const x = exec;\n`,
  },
  {
    name: "import 'node:module'",
    code: `import { createRequire } from 'node:module';\nexport const x = createRequire;\n`,
  },
  {
    name: "import 'undici'",
    code: `import { request } from 'undici';\nexport const x = request;\n`,
  },
  {
    name: "import 'undici/index.js' (subpath walks past an exact-specifier ban)",
    code: `import { request } from 'undici/index.js';\nexport const x = request;\n`,
  },
  { name: "import 'axios'", code: `import axios from 'axios';\nexport const x = axios;\n` },
  { name: "import 'node-fetch'", code: `import f from 'node-fetch';\nexport const x = f;\n` },
]);

const AXIS_1_DYNAMIC: BlockedRow[] = blockedBy(ZONE.auth, 'no-restricted-syntax', [
  { name: "await import('node:http')", code: `export const m = await import('node:http');\n` },
  {
    name: "await import(s) where s = 'node:http' (no literal to match)",
    code: `const s = 'node:http';\nexport const m = await import(s);\n`,
  },
  {
    name: "await import('node:' + 'http') (no literal to match)",
    code: `export const m = await import('node:' + 'http');\n`,
  },
]);

describe('axis 1: module specifier', () => {
  it.each(AXIS_1_MODULE_SPECIFIER)('blocks $name', expectBlocked);
  it.each(AXIS_1_DYNAMIC)('blocks $name', expectBlocked);
});

/* --- Axis 2: reference form -----------------------------------------------------------------
 * `no-restricted-globals` sees only a bare identifier. Everything below reaches the same
 * function through a receiver, and each form needs its own selector. */

const AXIS_2_REFERENCE_FORM: BlockedRow[] = blocked(ZONE.auth, [
  {
    name: 'bare fetch',
    code: `export const r = await fetch('https://x');\n`,
    rule: 'no-restricted-globals',
  },
  {
    name: 'globalThis.fetch',
    code: `export const r = await globalThis.fetch('https://x');\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: "globalThis['fetch']",
    code: `export const r = await globalThis['fetch']('https://x');\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'const g = globalThis',
    code: `const g = globalThis;\nexport const r = g.fetch;\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'const { fetch } = globalThis',
    code: `const { fetch } = globalThis;\nexport const r = fetch;\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'const { fetch: send } = globalThis',
    code: `const { fetch: send } = globalThis;\nexport const r = send;\n`,
    rule: 'no-restricted-syntax',
  },
]);

describe('axis 2: reference form', () => {
  it.each(AXIS_2_REFERENCE_FORM)('blocks $name', expectBlocked);
});

/* --- Axis 3: receiver -----------------------------------------------------------------------
 * Every axis-2 form repeated against `global`, plus the productions the rule itself provokes:
 * once an alias errors, a cast, a later assignment and a parameter default are what get reached
 * for next. This axis is unbounded and these are the cheap high-traffic forms, not a closure. */

const AXIS_3_RECEIVER: BlockedRow[] = blockedBy(ZONE.auth, 'no-restricted-syntax', [
  { name: 'global.fetch', code: `export const r = await global.fetch('https://x');\n` },
  { name: "global['fetch']", code: `export const r = await global['fetch']('https://x');\n` },
  { name: 'const g = global', code: `const g = global;\nexport const r = g.fetch;\n` },
  {
    name: 'const { fetch } = global',
    code: `const { fetch } = global;\nexport const r = fetch;\n`,
  },
  {
    name: 'const { fetch: send } = global',
    code: `const { fetch: send } = global;\nexport const r = send;\n`,
  },
  {
    name: 'const g = globalThis as typeof globalThis',
    code: `const g = globalThis as typeof globalThis;\nexport const r = g;\n`,
  },
  {
    name: 'const g = global as typeof globalThis',
    code: `const g = global as typeof globalThis;\nexport const r = g;\n`,
  },
  { name: 'let g; g = globalThis', code: `let g;\ng = globalThis;\nexport const r = g;\n` },
  { name: 'let g; g = global', code: `let g;\ng = global;\nexport const r = g;\n` },
  {
    name: 'function f(g = globalThis)',
    code: `export function f(g = globalThis) {\n  return g;\n}\n`,
  },
  { name: 'function f(g = global)', code: `export function f(g = global) {\n  return g;\n}\n` },
]);

describe('axis 3: receiver', () => {
  it.each(AXIS_3_RECEIVER)('blocks $name', expectBlocked);
});

/* --- Axis 4: guarded identifier -------------------------------------------------------------
 * `fetch` is not the only global that opens a socket, and `WebSocket` needs no import at all, so
 * the module bans never see it. These rows fire on the identifier name and do not depend on the
 * global existing in the running Node version. */

const AXIS_4_GUARDED_IDENTIFIER: BlockedRow[] = blocked(ZONE.auth, [
  {
    name: 'new WebSocket(url)',
    code: `export const s = new WebSocket('wss://x');\n`,
    rule: 'no-restricted-globals',
  },
  {
    name: 'new globalThis.WebSocket(url)',
    code: `export const s = new globalThis.WebSocket('wss://x');\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'new EventSource(url)',
    code: `export const s = new EventSource('https://x');\n`,
    rule: 'no-restricted-globals',
  },
  {
    name: 'new globalThis.EventSource(url)',
    code: `export const s = new globalThis.EventSource('https://x');\n`,
    rule: 'no-restricted-syntax',
  },
]);

describe('axis 4: guarded identifier', () => {
  it.each(AXIS_4_GUARDED_IDENTIFIER)('blocks $name', expectBlocked);
});

/* --- The tools zone -------------------------------------------------------------------------
 * A `files:` override REPLACES a rule's options rather than merging them, and src/tools/**
 * overrides `no-restricted-syntax` for its own description check. If the egress selectors were
 * not restated there, they would be silently absent in a directory where they matter most. */

const TOOLS_ZONE: BlockedRow[] = blocked(ZONE.tools, [
  {
    name: 'bare fetch',
    code: `export const r = await fetch('https://x');\n`,
    rule: 'no-restricted-globals',
  },
  {
    name: 'const g = globalThis',
    code: `const g = globalThis;\nexport const r = g.fetch;\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'await import(s) with a non-literal specifier',
    code: `const s = 'node:http';\nexport const m = await import(s);\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: "import 'undici'",
    code: `import { request } from 'undici';\nexport const x = request;\n`,
    rule: 'no-restricted-imports',
  },
]);

describe('the tools zone still carries the egress selectors', () => {
  it.each(TOOLS_ZONE)('blocks $name', expectBlocked);
});

/* --- The one egress door --------------------------------------------------------------------
 * These are the rows that stop the suite being satisfied by a rule that refuses everything. */

const DOOR_PERMITTED: CleanRow[] = clean(ZONE.door, [
  { name: 'bare fetch', code: `export const r = await fetch('https://x');\n` },
  { name: 'globalThis.fetch', code: `export const r = await globalThis.fetch('https://x');\n` },
  { name: 'const g = globalThis', code: `const g = globalThis;\nexport const r = g.fetch;\n` },
  {
    name: 'const { fetch } = globalThis',
    code: `const { fetch } = globalThis;\nexport const r = fetch;\n`,
  },
  {
    name: "import 'undici'",
    code: `import { request } from 'undici';\nexport const x = request;\n`,
  },
  { name: "import 'node:http'", code: `import http from 'node:http';\nexport const x = http;\n` },
  { name: "await import('node:http')", code: `export const m = await import('node:http');\n` },
  { name: 'new WebSocket(url)', code: `export const s = new WebSocket('wss://x');\n` },
]);

/**
 * The exemption is composed, not switched off. These rows are what catches someone simplifying
 * it back to `'off'`, which would leave the single module allowed to call out as the single
 * module free to import a tool or read config directly.
 */
const DOOR_STILL_BLOCKED: BlockedRow[] = blockedBy(ZONE.door, 'no-restricted-imports', [
  {
    name: "import '../config/index.ts'",
    code: `import { config } from '../config/index.ts';\nexport const x = config;\n`,
  },
  {
    name: 'import a tool module',
    code: `import { tool } from '../tools/getMealPlan.ts';\nexport const x = tool;\n`,
  },
  {
    name: 'import estate middleware',
    code: `import cors from 'cors';\nexport const x = cors;\n`,
  },
]);

describe('the one egress door', () => {
  it.each(DOOR_PERMITTED)('permits $name', expectClean);
  it.each(DOOR_STILL_BLOCKED)('still blocks $name', expectBlocked);
});

/* --- The test zone --------------------------------------------------------------------------
 * Imports are exempt so tests can use MockAgent. The call-out guard stays on: whether
 * test/integration/** may reach the network is a separate decision and is not conceded here. */

const TEST_ZONE_PERMITTED: CleanRow[] = clean(ZONE.tests, [
  {
    name: "import 'undici'",
    code: `import { MockAgent } from 'undici';\nexport const x = MockAgent;\n`,
  },
  { name: "import 'node:http'", code: `import http from 'node:http';\nexport const x = http;\n` },
]);

const TEST_ZONE_BLOCKED: BlockedRow[] = blocked(ZONE.tests, [
  {
    name: 'bare fetch',
    code: `export const r = await fetch('https://x');\n`,
    rule: 'no-restricted-globals',
  },
  {
    name: 'globalThis.fetch',
    code: `export const r = await globalThis.fetch('https://x');\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'const g = globalThis',
    code: `const g = globalThis;\nexport const r = g.fetch;\n`,
    rule: 'no-restricted-syntax',
  },
  {
    name: 'new WebSocket(url)',
    code: `export const s = new WebSocket('wss://x');\n`,
    rule: 'no-restricted-globals',
  },
]);

describe('the test zone', () => {
  it.each(TEST_ZONE_PERMITTED)('permits $name', expectClean);
  it.each(TEST_ZONE_BLOCKED)('still blocks $name', expectBlocked);
});

/* --- Ordinary code --------------------------------------------------------------------------
 * The rule must not fire on code that goes nowhere near the network. */

const ORDINARY: CleanRow[] = clean(ZONE.auth, [
  { name: 'an object literal', code: `export const x = { a: 1 };\n` },
  {
    name: 'a feature check on a non-egress global',
    code: `export const x = typeof structuredClone === 'function';\n`,
  },
  { name: 'a property named global', code: `export const x = { global: 1 };\n` },
  {
    name: 'an ordinary relative import',
    code: `import { McpError } from '../errors.ts';\nexport const x = McpError;\n`,
  },
]);

describe('ordinary code', () => {
  it.each(ORDINARY)('permits $name', expectClean);
});
