/**
 * Unit tests for path discovery. No DSH runtime is needed.
 *
 * @module dsh-plugin-git-bash-rs/test/discovery
 */

import assert from 'node:assert/strict';
import { realpathSync } from 'node:fs';
import { test } from 'node:test';

import { GIT_BASH_PATH_ENV, gitBashCandidates, resolveGitBashPath } from '../lib/discovery.js';

test('candidates prefer Program Files, then per-user installs', () => {
  const candidates = gitBashCandidates({
    ProgramFiles: 'C:\\Program Files',
    LOCALAPPDATA: 'C:\\Users\\u\\AppData\\Local',
    PATH: '',
  });
  assert.ok(candidates.length > 0);
  assert.equal(candidates[0], 'C:\\Program Files\\Git\\bin\\bash.exe');
  assert.ok(candidates.some((c) => c.includes('AppData\\Local\\Programs\\Git')));
});

test('candidates include the usr/bin variant of each root', () => {
  const candidates = gitBashCandidates({ ProgramFiles: 'C:\\Program Files', PATH: '' });
  assert.ok(candidates.some((c) => c.endsWith('Git\\usr\\bin\\bash.exe')));
});

test('candidates never include the WSL launcher', () => {
  const candidates = gitBashCandidates({ ProgramFiles: 'C:\\Program Files', PATH: 'C:\\WINDOWS\\system32' });
  assert.ok(!candidates.some((c) => /system32[\\/]bash\.exe/iu.test(c)));
});

test('a git PATH entry contributes its install root', () => {
  const candidates = gitBashCandidates({ PATH: 'C:\\Tools\\Git\\cmd' });
  assert.ok(candidates.includes('C:\\Tools\\Git\\bin\\bash.exe'));
});

test('duplicates are removed', () => {
  const candidates = gitBashCandidates({
    ProgramFiles: 'C:\\Program Files',
    PATH: 'C:\\Program Files\\Git\\cmd',
  });
  const lower = candidates.map((c) => c.toLowerCase());
  assert.equal(new Set(lower).size, lower.length);
});

test('resolve honours the environment override', () => {
  // Any real executable works; the plugin only checks existence and access.
  const resolved = resolveGitBashPath(undefined, {
    platform: 'win32',
    env: { [GIT_BASH_PATH_ENV]: process.execPath },
  });
  assert.equal(resolved.toLowerCase(), realpathSync.native(process.execPath).toLowerCase());
});

test('resolve rejects a configured path that does not exist', () => {
  assert.throws(
    () => resolveGitBashPath('C:\\nope\\bash.exe', { platform: 'win32', env: {} }),
    /does not exist or is not executable/u,
  );
});

test('resolve refuses non-Windows platforms', () => {
  assert.throws(
    () => resolveGitBashPath(undefined, { platform: 'linux', env: {} }),
    /supported only on Windows/u,
  );
});

test('the not-found error names the locations that were checked', () => {
  assert.throws(
    () => resolveGitBashPath(undefined, { platform: 'win32', env: { ProgramFiles: 'C:\\Nope' } }),
    (error) => error.message.includes('Checked:') && error.message.includes('C:\\Nope\\Git\\bin\\bash.exe'),
  );
});
