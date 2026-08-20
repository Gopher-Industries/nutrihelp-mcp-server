/**
 * The branch bars over the gated source directories, asserted as **wired** rather than as
 * configured. Ticket 68.
 *
 * A declared threshold is not an evaluated one. `coverage:auth` is the only command that evaluates
 * the `src/auth/**` bar, and its guard checks that the coverage *data* is non-vacuous — nothing
 * checked that a threshold had been applied to it. Rename the config key and that command still
 * exits 0, printing a confident branch figure over a bar that no longer exists. This file is what
 * goes red instead.
 *
 * **Placement is a deliberate departure from the mirroring convention:** this guards
 * `vitest.config.ts`, not a source module. It sits in the unit layer because `npm test` is chained
 * into `validate`, and `test/security/**` is not. The closest precedent, the frozen egress table,
 * guards a config file from the security layer and reaches a chained gate through `test:controls` —
 * which would need a **fourth** `&&`-joined invocation to carry this file too.
 *
 * **The bar's value is not restated here.** It lives in `vitest.config.ts`, and a second copy is two
 * hand-maintained records of one number that drift while each reads complete on its own.
 *
 * **What this file walks.** Six ways a declared bar stops guarding, each with a case behind it.
 * Every one of them ends the same way: a bar evaluating against nothing, or against the wrong files,
 * and exiting 0.
 *
 * 1. The `thresholds` key is renamed or deleted, so no glob is declared at all.
 * 2. A threshold glob is narrowed off a gated directory, so the bar holds nothing to evaluate.
 * 3. A threshold glob reaches past the gated directories, averaging the bar across modules the
 *    policy gives no floor. Checked over **every** declared glob rather than only the covering ones,
 *    so a bar declared for a directory `GATED_DIRS` does not name is caught too — but only once that
 *    directory holds a source on disk, because the check works by intersecting real files.
 * 4. The bar itself is absent, non-numeric, zero or negative — declared, evaluated, and passing
 *    unconditionally.
 * 5. `coverage.include` is narrowed off a gated directory, **or deleted** — which narrows rather than
 *    widens, for the reason `isMeasured` sets out.
 * 6. No report is written (`reportOnFailure` false): red-by-design cases fail the run first, so
 *    routes 1–5 never evaluate.
 *
 * A **seventh** route, `coverage.exclude`, is **foreclosed rather than walked**: it is asserted
 * absent, because the runner matches it in a way this file deliberately does not model. See that
 * case and `selects`.
 *
 * **`json-summary` is not a route** — missing it does not stop the bar firing; it only makes a
 * 100% file look like an empty glob under the text reporter's `skipFull` default.
 *
 * **What it does not do.** Stated because the list above must not read as closed — the standing
 * lesson here is that enumerating one axis exhaustively reads exactly like enumerating every axis.
 *
 * - **It cannot prove a bar fires.** That needs a branch dropped below the bar and the coverage
 *   command observed exiting non-zero, which is a mutation rather than an assertion.
 * - **It does not use the runner's matchers.** Globs are resolved with `node:fs` against the real
 *   tree, while the runner uses picomatch and tinyglobby with different options per call site. Both
 *   directions of divergence exist and the likelier one is benign: `globSync` is the narrower
 *   dialect and returns only paths that exist, so a pattern picomatch matches and `globSync` does not
 *   enumerate surfaces as a **false red** here. The disarming direction — reading as covering while
 *   the runner selects nothing — is the rarer one. Treat a surprising red as a dialect artefact
 *   before treating it as a real disarm.
 * - **It reads the declared config, and the CLI is the larger half of that gap.** The runner appends
 *   its own patterns to `coverage.exclude`, but more importantly `--coverage.include`,
 *   `--coverage.exclude` and `--coverage.thresholds.*` override the declared values outright — and
 *   `coverage:auth`, the one command that evaluates these bars, already passes coverage flags on its
 *   command line. Measured: adding `--coverage.exclude=src/auth/**` there drops every `src/auth/`
 *   file from the report while every case in this file stays green. A bar can be disarmed in the npm
 *   script without this file seeing it, because the flags live one layer outside where it looks.
 * - **`GATED_DIRS` is a second copy of the coverage policy**, maintained here by hand. What survives
 *   route 3 is its quiet half: gating a directory in the policy while declaring **no bar at all** for
 *   it, or declaring one over a directory that is still empty, goes unnoticed here. Same
 *   two-hand-maintained-lists drift this file catches one instance of.
 */

import { existsSync, globSync, readdirSync } from 'node:fs';
import { join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import config from '../../vitest.config.ts';

/** Repository root. Both `coverage.include` and the threshold globs resolve from here. */
const ROOT = fileURLToPath(new URL('../../', import.meta.url));

/** The directories the coverage policy puts a branch floor on. Nothing else carries one. */
const GATED_DIRS = ['src/auth', 'src/tools'] as const;

/**
 * Every key of `thresholds` is a glob except these: the four metric names carry the global values
 * and the other two are switches. Held in step with the runner's own reserved list — a key it
 * reserves, read here as a glob, would select nothing and read as a bar covering nothing. Drift here
 * is harmless: it can only change the glob list quoted in a failure message.
 */
const RESERVED_KEYS = new Set([
  'lines',
  'functions',
  'statements',
  'branches',
  'perFile',
  'autoUpdate',
  '100',
]);

/** Posix-separated and root-relative: the form threshold globs are matched against. */
function toPosix(entry: string): string {
  return entry.split(sep).join('/');
}

const selectionCache = new Map<string, Set<string>>();

/**
 * The paths a glob selects, memoized per pattern.
 *
 * Resolved against the real filesystem rather than with the runner's own matcher. `picomatch` is
 * what the runner uses and it does resolve from here — but it is an **undeclared transitive** of the
 * test runner, so pinning a gate's correctness to it trades one silent failure for another that the
 * lockfile can introduce without notice. `globSync` walks the real tree, so a declared `include` of
 * `'**'` would walk `node_modules` with it.
 *
 * **The runner matches these globs at three call sites, with different inputs and different options.
 * They must not be conflated:**
 *
 * - **Threshold globs** are matched with `pm(glob)` — **no options** — against the **root-relative
 *   posix** path. That is exactly what `globSync(glob, { cwd: ROOT })` enumerates, so the model fits
 *   well, and every threshold-glob assertion in this file rests on it. Posix because the runner takes
 *   `relative` from `pathe`, not `node:path`: under `node:path` this matcher would be handed
 *   backslashes on Windows and select nothing, and an empty threshold set reports 100%. That is a
 *   second mirror that fails **unsafe** — re-check it on a runner major.
 * - **The untested-file walk** hands `include` to tinyglobby as `glob(include, { cwd: root, ... })`,
 *   which is **cwd-relative**, the same frame `globSync` uses here. This is the call site the whole
 *   `include` argument in `isMeasured` hangs on, and this function models it structurally rather
 *   than by coincidence.
 * - **`coverage.include` and `coverage.exclude` as a filter over the map** are matched with
 *   `pm.isMatch(file, include || '**', { contains: true, dot: true, ignore: exclude })`, against the
 *   **absolute** slashed path. `contains: true` is the difference that bites: `'auth/**'` selects
 *   nothing when resolved from the repository root here, while the runner matches it *inside* the
 *   absolute path and drops every file under `src/auth/`. The two disagree, and they disagree in the
 *   disarming direction — this file would call those sources measured while the bar behind them
 *   evaluated against nothing.
 *
 * `isMeasured` therefore uses this for `include` only. On the admission path above the frames agree
 * structurally; on the contains-based filter it is the declared `'src/**'` that happens to resolve
 * the same way, which is a property of the current value rather than of the model — so that case
 * checks a declared pattern rather than claiming a proof. `exclude` is asserted absent instead of
 * modelled, because modelling it means reimplementing picomatch.
 */
function selects(glob: string): Set<string> {
  const cached = selectionCache.get(glob);
  if (cached !== undefined) return cached;
  const selected = new Set(globSync(glob, { cwd: ROOT }).map(toPosix));
  selectionCache.set(glob, selected);
  return selected;
}

/** Source files that exist under `dir`, root-relative. Read from disk, so no second list is
 *  maintained here beside the one in the tree. */
function sourcesUnder(dir: string): string[] {
  if (!existsSync(join(ROOT, dir))) return [];
  return readdirSync(join(ROOT, dir), { recursive: true, encoding: 'utf8' })
    .map(toPosix)
    .filter((entry) => entry.endsWith('.ts'))
    .map((entry) => `${dir}/${entry}`)
    .sort();
}

/**
 * The resolved `coverage` block.
 *
 * Throws rather than degrading to an empty one: a config moved to the callback form
 * (`defineConfig(() => ({ ... }))`), or one that splits coverage into a projects file, would
 * otherwise read here as a deleted threshold — a correct red pointing at a deletion that never
 * happened.
 */
function coverageOptions(): {
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
  readonly thresholds?: unknown;
  readonly reportOnFailure?: boolean;
  /** Bare name, array, or `[name, options]` tuples — keep `unknown` so tuple form stays covered. */
  readonly reporter?: unknown;
} {
  const coverage = config.test?.coverage;
  if (coverage === undefined) {
    throw new Error(
      'no test.coverage block was readable from the vitest config. Reading that as an absent ' +
        'threshold would diagnose the wrong defect: check whether the config moved to the callback ' +
        'form, or whether coverage moved into a projects file.'
    );
  }
  return coverage;
}

/** Reporter names from bare / array / `[name, options]` shapes. */
function declaredReporters(): readonly string[] {
  const declared: unknown = coverageOptions().reporter;
  const entries: readonly unknown[] = Array.isArray(declared) ? declared : [declared];
  return entries
    .map((entry) => (Array.isArray(entry) ? (entry as readonly unknown[])[0] : entry))
    .filter((name): name is string => typeof name === 'string');
}

/**
 * The branch percentage a glob entry carries, by the runner's own rules: `{ 100: true }` sets all
 * four metrics, otherwise only a numeric `branches` counts.
 *
 * This is the half of the mirroring in this file that fails **unsafe** if the runner's shorthand
 * changes — a shape mirrored wrongly here reports a bar the runner does not apply, which is a false
 * green in a file written to prevent one. Re-check it on a runner major.
 */
function branchThreshold(entry: unknown): number | undefined {
  if (entry === null || typeof entry !== 'object') return undefined;
  const shaped = entry as { readonly branches?: unknown; readonly 100?: unknown };
  if (shaped[100] === true) return 100;
  return typeof shaped.branches === 'number' ? shaped.branches : undefined;
}

/** The `thresholds` block as glob-candidate entries, or none when the key is absent or renamed. */
function thresholdEntries(): [string, unknown][] {
  const declared = coverageOptions().thresholds;
  if (declared === null || typeof declared !== 'object') return [];
  return Object.entries(declared).filter(([key]) => !RESERVED_KEYS.has(key));
}

/**
 * Whether the coverage report measures `file`, judged from the **declared** `coverage.include`.
 *
 * A declared `include` can hide a source the obvious way: narrow it off a directory and those files
 * drop out of the report, so a threshold over them matches nothing and passes with no data behind
 * it.
 *
 * **An absent `include` hides more, not less, and that is the opposite of how it reads.** The key
 * feeds two different filters and only one of them falls back to `**`:
 *
 * - As a **filter over files already in the coverage map**, the runner reads it as `include || '**'`.
 *   That fallback is real. It is also load-scoped: it can only keep or drop files some test already
 *   imported.
 * - As the **gate that admits untested files**, an absent `include` admits nothing. The walk that
 *   collects untested files returns an empty list outright when the key is null, and the merge of
 *   that list into the map is guarded on the same null check.
 *
 * So deleting the key does not widen the report to everything — it silently narrows it to whatever
 * the tests happened to load. A new module under a gated directory **with no test at all** then
 * never enters the coverage map, the directory's bar aggregates only the tested files beside it,
 * clears 90 and exits 0. Catching an untested authorization module is the most valuable thing that
 * bar does, so absent must read here as **not measured**: `include` has to be present *and* select
 * the file.
 *
 * The load-scoped fallback is the trap in this reasoning, and it is a real line of runner code
 * governing a different code path — the one that filters the map, not the one that fills it. A
 * previous round read it as authority for treating absent as permissive.
 *
 * `exclude` is not consulted here. It reaches the same silent pass from the other side and is
 * foreclosed by its own case below rather than modelled, for reasons `selects` gives.
 */
function isMeasured(file: string): boolean {
  const { include } = coverageOptions();
  // `?? false`, never `?? true`: an absent `include` is the narrowing case, not the permissive one.
  return include?.some((glob) => selects(glob).has(file)) ?? false;
}

/** Gated directories that carry sources today. A bar over an empty directory cannot be proved
 *  wired, only pinned — which is the last case in this file. */
const POPULATED = GATED_DIRS.map((dir) => ({ dir, sources: sourcesUnder(dir) })).filter(
  (entry) => entry.sources.length > 0
);

const ALL_GATED_SOURCES = POPULATED.flatMap((entry) => entry.sources);

/** Sources under `src/` that no floor is meant to cover. Thresholds are aggregate unless `perFile`
 *  is set, so a gated glob widened onto these averages the bar with modules that have no floor. */
const UNGATED_SOURCES = sourcesUnder('src').filter(
  (file) => !GATED_DIRS.some((dir) => file.startsWith(`${dir}/`))
);

/**
 * Covers when the glob selects every one of `files`.
 *
 * The empty case throws rather than returning: `[].every(...)` is `true`, so an empty file set would
 * report every glob — including one pointed at nothing — as covering. Guarded here rather than in a
 * preceding case, because a guard in another `it` is not a guard when this one runs first.
 */
function covers(glob: string, files: readonly string[]): boolean {
  if (files.length === 0) {
    throw new Error('covers() over an empty file set would report every glob as covering it');
  }
  const selected = selects(glob);
  return files.every((file) => selected.has(file));
}

describe('the coverage branch bars over the gated directories', () => {
  it('measures every gated source that exists', () => {
    expect(
      POPULATED,
      'at least one gated directory must carry sources, or every assertion in this file is about an empty set and guards nothing'
    ).not.toHaveLength(0);

    for (const { dir, sources } of POPULATED) {
      expect(
        sources.filter((file) => !isMeasured(file)),
        `every source under ${dir} must reach the coverage report. A file the report never measures cannot fail a threshold, so narrowing coverage.include off it disarms the bar as effectively as deleting the key. DELETING coverage.include does the same thing, which is the opposite of how it reads: the fallback to '**' is scoped to files a test already loaded, while the separate walk that admits UNTESTED files returns nothing at all when the key is null. An untested module under ${dir} would then never enter the report to be measured, and the bar would clear on its tested neighbours alone`
      ).toEqual([]);
    }
  });

  it('declares no coverage.exclude, so none can be widened onto a gated source', () => {
    expect(
      coverageOptions().exclude ?? [],
      'coverage.exclude must stay absent or empty. It is deliberately NOT modelled in this file: the runner matches it with picomatch under `contains: true` against the ABSOLUTE path, so an entry like "auth/**" selects nothing when resolved from the repository root here while the runner matches it inside the absolute path and drops every file under src/auth/. This file would then report those sources measured while their bar evaluated against nothing — the exact silent pass it exists to catch. Adding an entry is therefore a change that has to be proved by hand not to reach a gated source, not one this case can check for you. Note also that the runner APPENDS its own patterns to this list — setup files, the test include glob, the config file, **/virtual:*, **/__x00__* and **/node_modules/** — so the effective exclude is always wider than the declared one read here; nothing it appends reaches a gated source today. A CLI --coverage.exclude overrides this declared value entirely and is invisible here, which is why the file header names that as a residue rather than a covered route'
    ).toEqual([]);
  });

  it('declares a branch bar covering each gated directory, and does not spread it beyond them', () => {
    // Negative control: `covers` has to discriminate. A matcher that selected everything would make
    // the search below succeed against any declared key, including one pointed somewhere else.
    expect(
      covers('src/config/**', ALL_GATED_SOURCES),
      'a glob outside the gated directories must NOT count as covering them. If it does, the search below is satisfied by any threshold key at all and this case asserts nothing'
    ).toBe(false);
    expect(
      UNGATED_SOURCES,
      'src/ must carry sources outside the gated directories, or the spread assertion below has nothing to detect and passes for the wrong reason'
    ).not.toHaveLength(0);

    const globs = thresholdEntries();
    const declared = JSON.stringify(globs.map(([glob]) => glob));

    // Runs over EVERY declared glob, outside the per-directory loop below, because that loop only
    // ever reaches globs that cover a gated directory. A bar declared for a directory GATED_DIRS
    // does not name — `src/upstream/**`, say — gets no covering check, no bar check and no spread
    // check from it, and lands silently. Same two-hand-maintained-lists drift as the egress
    // exemptions: the threshold block and GATED_DIRS are two records of one policy.
    // Positive control for the assertion below, which is `filter(...) -> toEqual([])` and would pass
    // just as readily if `selects` and `sourcesUnder` disagreed on path form and never intersected
    // at all. Neither guard above closes that: the negative control asserts `false`, which a wholly
    // broken matcher also satisfies, and a non-empty UNGATED_SOURCES only says the tree has ungated
    // files. This pins the two to the same path form for the very set the filter searches.
    expect(
      UNGATED_SOURCES.some((file) => selects('src/**').has(file)),
      'selects() and sourcesUnder() must agree on path form over the ungated sources, or the spread assertion below is empty for the wrong reason and detects nothing'
    ).toBe(true);

    const spreading = globs
      .map(([glob]) => glob)
      .filter((glob) => UNGATED_SOURCES.some((file) => selects(glob).has(file)));
    expect(
      spreading,
      `no declared threshold glob may reach a source outside ${GATED_DIRS.join(' and ')}. Thresholds are aggregate unless perFile is set, so a glob reaching an ungated module averages a gated directory together with code the policy gives no floor, and the bar stops meaning what it says. This runs over every declared glob rather than only the ones covering a gated directory, because a bar declared over an ungated directory is checked by nothing else in this file. Gating a new directory is a policy change: add it to GATED_DIRS in the same edit that declares its bar, so it is covered here rather than merely tolerated. Declared globs: ${declared}`
    ).toEqual([]);

    for (const { dir, sources } of POPULATED) {
      const covering = globs.filter(([glob]) => covers(glob, sources));
      expect(
        covering.map(([glob]) => glob),
        `a threshold glob must cover every source under ${dir}. Renaming the thresholds key, or narrowing its glob, leaves the coverage command exiting 0 on a confident figure with no bar behind it. Declared globs: ${declared}`
      ).not.toHaveLength(0);

      const withBar = covering.filter(([, entry]) => {
        const bar = branchThreshold(entry);
        return bar !== undefined && bar > 0;
      });
      expect(
        withBar.map(([glob]) => glob),
        `the threshold covering ${dir} must carry a branch bar above zero. Absent, non-numeric or 0 is a key that evaluates and passes unconditionally; a NEGATIVE value is a maximum-uncovered count rather than a percentage floor, and this project gates a percentage, so it reads here as a policy change rather than as a bar. The value itself belongs in vitest.config.ts and is not asserted here`
      ).not.toHaveLength(0);
    }
  });

  it('writes a report even when the run fails, or the bar evaluates against nothing', () => {
    expect(coverageOptions().reportOnFailure).toBe(true);
  });

  it('emits the one report format the doc set tells everyone to read', () => {
    expect(declaredReporters()).toContain('json-summary');
  });

  /**
   * `src/tools` is gated by policy and carries a declared bar, but holds no source, so the cases
   * above cannot prove that bar wired — they can only pass over it. What is asserted instead is the
   * fact that makes it inert, so this case turns red on the day the directory appears, which is the
   * day the bar becomes provable.
   */
  it('carries no tool source yet, so the bar declared over them is pinned rather than proven', () => {
    expect(
      sourcesUnder('src/tools'),
      'a source landed under src/tools. The cases above now pick it up on their own, so its declared bar is being asserted as wired for the first time: prove it FIRES by dropping a branch there below the bar and confirming the coverage command exits non-zero, then delete this case'
    ).toEqual([]);
  });
});
