/**
 * Agent-adapter prompt tests.
 *
 * Two things matter here. The prompt must carry the Git Bash / Linux traps, and
 * it must tell the model about the one exit-code remap this plugin introduces,
 * because a model that silently misreads an exit marker produces confident
 * wrong conclusions.
 *
 * The assertions check for the *facts* the prompt has to convey rather than its
 * exact wording, so the text can be rephrased without breaking the suite while
 * dropping a fact still fails.
 *
 * @module dsh-plugin-git-bash-rs/test/agents.test.mjs
 */

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { test } from 'node:test';

const agentsUrl = new URL('../lib/agents.js', import.meta.url);
const available = existsSync(new URL('../lib/agents.js', import.meta.url));

/** Load the adapter module. */
async function loadAgents() {
  return import(agentsUrl.href);
}

test('the adapter declares its name and injected services', { skip: !available }, async () => {
  const module = await loadAgents();
  assert.equal(module.name, 'git-bash-agent-shell');
  assert.deepEqual([...module.inject].sort(), ['agents', 'systemPrompt', 'tools']);
});

test('the prompt tells the model to read the exit marker', { skip: !available }, async () => {
  const { BASH_SECTION } = await loadAgents();
  assert.ok(BASH_SECTION.includes('[exit code: N]'), 'the marker name must appear');
});

test('the prompt states the 125 to 126 remap exists', { skip: !available }, async () => {
  // The guard maps a child's 125 to 126 so that 125 stays a reliable
  // runner-failure signal. A model that does not know this reports the wrong
  // code back to the user.
  const { BASH_SECTION } = await loadAgents();
  assert.ok(
    /\b125\b[^.]*\b126\b|\b126\b[^.]*\b125\b/u.test(BASH_SECTION),
    'the remap from 125 to 126 must be stated',
  );
});

test('the prompt scopes the remap to confined runs', { skip: !available }, async () => {
  // `danger-full-access` bypasses the guard entirely, so a command's 125 stays
  // 125 there. Without this the rule would be wrong in that mode.
  const { BASH_SECTION } = await loadAgents();
  assert.ok(/confin/iu.test(BASH_SECTION), 'the remap must be attributed to confinement');
  assert.ok(/unconfined/iu.test(BASH_SECTION), 'unconfined runs must be excluded explicitly');
});

test('the prompt sends the model to stderr for the real cause', { skip: !available }, async () => {
  const { BASH_SECTION } = await loadAgents();
  assert.ok(/stderr/iu.test(BASH_SECTION), 'the model must be pointed at stderr');
});

test('the prompt does not claim a runner failure is always a tool error', { skip: !available }, async () => {
  // A readiness-handshake timeout resumes the child before the guard kills it
  // (main.rs: resume() then await_hook_ready()), so that failure is not simply
  // "the command never ran" and must not be described as one.
  const { BASH_SECTION } = await loadAgents();
  assert.ok(
    !/tool error, not an exit marker/u.test(BASH_SECTION),
    'the prompt must not assert a uniform tool-error shape for runner failures',
  );
});

test('the prompt still carries the Git Bash versus Linux traps', { skip: !available }, async () => {
  const { BASH_SECTION } = await loadAgents();
  for (const phrase of ['MSYS2', '/c/...', 'CRLF']) {
    assert.ok(BASH_SECTION.includes(phrase), `guidance must still mention ${phrase}`);
  }
});
