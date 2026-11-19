/**
 * Client-half tests.
 *
 * The compiled `lib/client.js` is not an ES module: DSH's client loader evaluates it and
 * calls the factory with the modules the plugin declares. The suite therefore
 * installs a minimal `window.__ModuleLoader__` stub, evaluates the file in a
 * separate context, and exercises the factory directly. That catches the
 * failure that actually happens in practice — a client half that throws on
 * load and takes the plugin's UI down with it.
 *
 * The stylesheet is tested against the *shipped* markup rather than its own
 * text: a rule keyed off a class name that the real row never renders applies
 * to nothing and fails silently, which is exactly the bug this suite exists to
 * prevent.
 *
 * @module dsh-plugin-git-bash-rs/test/client.test.mjs
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../lib/client.js', import.meta.url), 'utf8');

/**
 * Evaluate `client.js` and return what its factory exports.
 * @param {object} [options] - `require` override, plus a `document` stub.
 */
function loadClient(options = {}) {
  let registered;
  const window = {
    __ModuleLoader__: {
      load: (definition) => {
        registered = definition;
      },
    },
  };
  const globals = { window };
  if (options.document !== undefined) globals.document = options.document;
  const require = options.require ?? (() => {
    throw new Error('the client half must not require anything');
  });
  runInNewContext(source, globals, { filename: 'lib/client.js' });
  assert.ok(registered !== undefined, 'lib/client.js must call window.__ModuleLoader__.load');
  return { definition: registered, module: registered.factory(require) };
}

/** A minimal `document` that records style elements. */
function stubDocument() {
  const appended = [];
  const byId = new Map();
  return {
    appended,
    createElement: (tag) => ({ tag, id: '', textContent: '', remove() { byId.delete(this.id); } }),
    getElementById: (id) => byId.get(id) ?? null,
    head: {
      appendChild(element) {
        appended.push(element);
        byId.set(element.id, element);
      },
    },
  };
}

test('the module loader registration names this package', () => {
  // The loader keys factories by installation id and throws
  // "loaded without registering <id>" when the two disagree.
  const { definition } = loadClient();
  assert.equal(definition.id, 'dsh-plugin-git-bash-rs');
  assert.equal(typeof definition.factory, 'function');
});

test('the factory exports apply and an empty inject list', () => {
  const { module } = loadClient();
  assert.equal(typeof module.apply, 'function');
  // Nothing is injected: the feature is a stylesheet, not a slot contribution.
  assert.deepEqual([...module.inject], []);
});

test('the client half requires nothing from the module loader', () => {
  // A require() of react or a client package would need dsh.client.inject to
  // list it; requiring nothing keeps the load order irrelevant.
  loadClient();
});

test('apply installs the stylesheet through an effect', () => {
  const document = stubDocument();
  const { module } = loadClient({ document });
  const disposers = [];
  const ctx = { effect: (run) => { disposers.push(run()); } };
  module.apply(ctx);

  assert.equal(document.appended.length, 1);
  assert.equal(document.appended[0].tag, 'style');
  assert.equal(document.appended[0].id, 'dsh-plugin-git-bash-rs-command-wrap');
  assert.ok(document.appended[0].textContent.includes('[data-sample="bash"]'));
  assert.equal(disposers.length, 1, 'the style must be disposable');
});

test('apply is inert without a document', () => {
  // Server-side evaluation of this file must not throw.
  const { module } = loadClient();
  const disposers = [];
  const ctx = { effect: (run) => { disposers.push(run()); } };
  assert.doesNotThrow(() => module.apply(ctx));
  assert.equal(typeof disposers[0], 'function');
});

test('the stylesheet targets markup the shipped bash row actually renders', () => {
  // `data-sample="bash"` is a literal attribute in bash-sample.tsx of
  // @deepseek-ai/dsh-client-ui-tool, and its CSS modules hash to names that
  // still contain the plain local name (`CY-8Ka_summary`, `CY-8Ka_ioText`).
  // If upstream renames either, the rule silently stops applying, so pin every
  // selector to a real name.
  const document = stubDocument();
  const { module } = loadClient({ document });
  module.apply({ effect: (run) => run() });
  const css = document.appended[0].textContent;

  // Names taken from the shipped package, not invented here.
  for (const fragment of ['summary', 'ioText', 'data-command-text', 'data-sample="bash"']) {
    assert.ok(css.includes(fragment), `stylesheet must reference the shipped name ${fragment}`);
  }
});

test('the summary rule wraps AND the row can grow to hold the wrapped text', () => {
  // Overriding `white-space` alone is not enough: the shipped `.root` pins its
  // height to one text line, so wrapped lines would paint outside the row. Both
  // declarations are part of the fix and are asserted separately, because a
  // mutation that keeps one and drops the other must fail.
  const document = stubDocument();
  const { module } = loadClient({ document });
  module.apply({ effect: (run) => run() });
  const css = document.appended[0].textContent;

  const rules = css.split('}').map((rule) => rule.trim()).filter((rule) => rule.length > 0);
  const summaryRule = rules.find((rule) => rule.includes('[class*="summary"]'));
  assert.ok(summaryRule !== undefined, 'the summary rule must exist');
  assert.match(summaryRule, /white-space:\s*pre-wrap/u, 'the summary must be allowed to wrap');
  assert.match(summaryRule, /overflow-wrap:\s*anywhere/u, 'a long unbroken path must break');
  assert.match(summaryRule, /overflow:\s*visible/u, 'a wrapped summary must not be clipped');

  // The height relaxation lives on the row itself, not on the summary.
  const rowRule = rules.find((rule) => /\[data-sample="bash"\]\s*\{/u.test(rule));
  assert.ok(rowRule !== undefined, 'a rule must target the bash row element itself');
  assert.match(rowRule, /height:\s*auto/u, 'the row must be allowed to grow');
  assert.match(rowRule, /min-height:/u, 'the single-line height must be kept as a floor');
});

test('isGitBashExecutablePath matches the host-side rule', () => {
  const { module } = loadClient();
  for (const value of [
    'C:\\Program Files\\Git\\bin\\bash.exe',
    'C:/Program Files/Git/bin/bash.exe',
    '\\\\server\\share\\Git\\bin\\bash.exe',
    '%ProgramFiles%\\Git\\bin\\bash.exe',
  ]) {
    assert.equal(module.isGitBashExecutablePath(value), true, `must accept ${value}`);
  }
  for (const value of [
    '',
    'bash.exe',
    'relative\\bash.exe',
    'C:\\Program Files\\Git\\bin\\sh.exe',
    '/usr/bin/bash.exe',
  ]) {
    assert.equal(module.isGitBashExecutablePath(value), false, `must reject ${value}`);
  }
});

test('gitBashExecutableFromDirectory resolves each plausible picker result', () => {
  const { module } = loadClient();
  const cases = [
    ['C:\\Program Files\\Git', 'C:\\Program Files\\Git\\bin\\bash.exe'],
    ['C:\\Program Files\\Git\\bin', 'C:\\Program Files\\Git\\bin\\bash.exe'],
    ['C:\\Program Files\\Git\\usr', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'],
    ['C:\\Program Files\\Git\\usr\\bin\\bash.exe', 'C:\\Program Files\\Git\\usr\\bin\\bash.exe'],
    ['C:/Program Files/Git/', 'C:\\Program Files\\Git\\bin\\bash.exe'],
    ['D:', 'D:\\bin\\bash.exe'],
    ['', ''],
    ['   ', ''],
  ];
  for (const [input, expected] of cases) {
    assert.equal(module.gitBashExecutableFromDirectory(input), expected, `input ${JSON.stringify(input)}`);
  }
});
