/**
 * Source-hygiene tests.
 *
 * These guard properties that a compiler will not: a comment header can be
 * concatenated with the line below it and still parse, so nothing fails until
 * someone looks. That happened here twice while adding SPDX headers — a
 * `-NoNewline` write produced `////!` in eight Rust files and a glued `/**` in
 * the JS modules — and the Rust side compiled cleanly throughout.
 *
 * @module dsh-plugin-git-bash-rs/test/hygiene.test.mjs
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** Directories that hold first-party source. */
const SOURCE_DIRS = ['src', 'native/guard/src', 'native/hook/src'];

/** First-party source files under `src/` plus the native crates. */
function sourceFiles() {
  const files = [];
  for (const dir of SOURCE_DIRS) {
    const absolute = join(ROOT, dir.split('/').join(sep));
    for (const entry of readdirSync(absolute)) {
      if (/\.(?:rs|ts)$/u.test(entry)) files.push(join(absolute, entry));
    }
  }
  return files;
}

/** Read a file as UTF-8 text with line endings normalised. */
function read(file) {
  return readFileSync(file, 'utf8').replace(/\r\n/gu, '\n');
}

test('every source file starts with an SPDX license identifier', () => {
  for (const file of sourceFiles()) {
    const first = read(file).split('\n')[0];
    assert.match(first, /^\/\/ SPDX-License-Identifier: MIT$/u, `${relative(ROOT, file)} must open with SPDX`);
  }
});

test('no source file has a doubled comment opener', () => {
  // `////!` is still a valid Rust doc comment and `//***` a valid JS comment,
  // so this cannot be caught by compiling.
  for (const file of sourceFiles()) {
    const text = read(file);
    assert.ok(!/^\/\/\/\//mu.test(text), `${relative(ROOT, file)} has a doubled comment opener`);
    assert.ok(!/^\/\/\*\*/mu.test(text), `${relative(ROOT, file)} has a glued JSDoc opener`);
  }
});

test('a documentation block never shares a line with the header comment', () => {
  // The header ends with a blank `//` line; the doc block must follow on its own.
  for (const file of sourceFiles()) {
    const lines = read(file).split('\n');
    for (const [index, line] of lines.entries()) {
      assert.ok(!/^\/\/[^/].*\/\/!/u.test(line), `${relative(ROOT, file)}:${index + 1} glues a //! block onto a comment`);
      assert.ok(!/^\/\/[^/].*\/\*\*$/u.test(line), `${relative(ROOT, file)}:${index + 1} glues a /** block onto a comment`);
    }
  }
});

test('the verbatim upstream licenses are present', () => {
  // MIT requires the upstream notices to travel with copies of the code, and
  // LICENSE/NOTICE both point at these files. Detours ships its text as
  // Markdown (`# MIT License`), so the heading marker is optional here.
  for (const name of ['dsh-git-bash-LICENSE', 'Detours-LICENSE']) {
    const file = join(ROOT, 'licenses', name);
    assert.ok(statSync(file).isFile(), `licenses/${name} must exist`);
    const text = read(file);
    assert.match(text, /^#? ?MIT License$/mu, `licenses/${name} must contain the MIT grant`);
    assert.match(text, /Copyright \(c\)/u, `licenses/${name} must carry a copyright line`);
  }
});

test('the plugin LICENSE carries both upstream copyright lines', () => {
  const text = read(join(ROOT, 'LICENSE'));
  assert.match(text, /^Copyright \(c\) 2026 vdiskg$/mu, 'the author notice');
  // Verbatim from dsh-git-bash, whose line has no name.
  assert.match(text, /^Copyright \(c\) 2026$/mu, 'the dsh-git-bash notice, verbatim');
  assert.match(text, /^Copyright \(c\) Microsoft Corporation\. All rights reserved\.$/mu, 'the Detours notice');
});
