/**
 * Fails the build when the running Node does not satisfy `engines.node`.
 *
 * WHY THIS EXISTS: `engines` is advisory, and `.node-version` is read only by nvm/fnm/Volta.
 * Both pins were documentation, and on 2026-08-11 two people verified the same security control
 * on Node 22.22.0 and 25.9.0 against a pin of `>=24.0.0 <25.0.0`. `@types/node` describes 24, so
 * `tsc` was validating an API the runtime was not providing, and a lint bypass that depends on
 * `process.getBuiltinModule` (Node 22.3+) is present or absent depending on who ran the probe.
 * `engine-strict=true` would live in `.npmrc`, which is banned here, so the pin is enforced from
 * a script instead.
 *
 * PLAIN JAVASCRIPT ON PURPOSE. This must run and print something useful on the versions it is
 * meant to reject. A `.ts` file cannot be type-stripped by Node 22 or earlier without a flag, so
 * it would die with a syntax error on exactly the versions that most need the explanation.
 *
 * NO SILENT PASS. An unparseable range fails closed. A guard that cannot evaluate its own
 * condition and exits 0 is the failure mode this repository keeps finding in its own harnesses.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pkgPath = fileURLToPath(new URL('../package.json', import.meta.url));
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
const range = pkg.engines?.node;

/** Only the two-clause form this project pins is understood. Anything else fails closed. */
const RANGE_RE = /^>=\s*(\d+)\.(\d+)\.(\d+)\s+<\s*(\d+)\.(\d+)\.(\d+)$/;

function fail(lines) {
  console.error('\n  Node version check failed.\n');
  for (const line of lines) console.error(`  ${line}`);
  console.error('');
  process.exit(1);
}

if (typeof range !== 'string') {
  fail([
    'package.json has no `engines.node`.',
    'This guard exists to enforce that pin, so its absence is a failure, not a pass.',
  ]);
}

const m = RANGE_RE.exec(range.trim());
if (!m) {
  fail([
    `engines.node is \`${range}\`, which this guard does not know how to evaluate.`,
    'Supported form: ">=X.Y.Z <A.B.C".',
    'Failing closed: a guard that cannot check its condition must not report success.',
  ]);
}

const [, loMaj, loMin, loPat, hiMaj, hiMin, hiPat] = m.map(Number);
const [maj, min, pat] = process.versions.node.split('.').map(Number);

const cmp = (a, b, c, x, y, z) => a - x || b - y || c - z;
const satisfied =
  cmp(maj, min, pat, loMaj, loMin, loPat) >= 0 && cmp(maj, min, pat, hiMaj, hiMin, hiPat) < 0;

if (!satisfied) {
  fail([
    `Running Node ${process.versions.node}; this project requires ${range}.`,
    '',
    '`.node-version` says 24 and `@types/node` describes 24, so on any other major',
    'the type checker and the runtime disagree about what exists.',
    '',
    'Fix: install Node 24 LTS, or use a version manager that reads `.node-version`',
    '(nvm, fnm, Volta) and run it in this directory.',
    '',
    'This check is deliberately not skippable. If it is in your way, the verification',
    'you are about to run would not have meant anything.',
  ]);
}

console.log(`node ${process.versions.node} satisfies engines.node ${range}`);
