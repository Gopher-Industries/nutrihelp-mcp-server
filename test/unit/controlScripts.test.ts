/**
 * Shape of `test:controls`: one `vitest run` per file, joined by `&&`.
 * A single `vitest run a b c` exits 0 when any named file is missing (substring filters).
 * File list is not pinned here — that is policy; the invariant is one file per invocation.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));

interface PackageManifest {
  readonly scripts?: Record<string, string>;
}

function script(name: string): string {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')) as PackageManifest;
  const value = manifest.scripts?.[name];
  if (value === undefined) {
    throw new Error(
      `package.json declares no \`${name}\` script. Reading that as a passing shape check would ` +
        'diagnose the wrong defect: the gate is absent, not merely misshapen.'
    );
  }
  return value;
}

/** Each `&&`-joined segment of the script, trimmed. */
function invocations(name: string): readonly string[] {
  return script(name)
    .split('&&')
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
}

/** Positional file args of one `vitest run …` segment, flags excluded. */
function filesNamedBy(invocation: string): readonly string[] {
  const [, ...rest] = invocation.split(/\s+/);
  return rest.filter((token) => token !== 'run' && !token.startsWith('-'));
}

const MINIMUM_CONTROL_INVOCATIONS = 3;

describe('the shape of test:controls', () => {
  it('runs vitest once per control file, never one command with several filters', () => {
    for (const invocation of invocations('test:controls')) {
      expect(filesNamedBy(invocation)).toHaveLength(1);
    }
  });

  it('keeps a floor under the number of chained invocations', () => {
    expect(invocations('test:controls').length).toBeGreaterThanOrEqual(MINIMUM_CONTROL_INVOCATIONS);
  });

  it('is chained into validate, or none of the above reaches anyone', () => {
    expect(script('validate')).toContain('test:controls');
  });

  it('names only files that exist, so a rename cannot leave a filter matching nothing', () => {
    for (const invocation of invocations('test:controls')) {
      for (const file of filesNamedBy(invocation)) {
        expect(existsSync(join(ROOT, file))).toBe(true);
      }
    }
  });
});
