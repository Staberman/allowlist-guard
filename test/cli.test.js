import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fakes, tempDir, writeSettings, run, ROOT } from './helpers.js';

const leaky = () => [
  'Bash(npm test)',
  `Bash(curl -H "Authorization: Bearer ${fakes.bearer}" https://api.test/v1)`,
  'Bash(git status)',
  `Bash(echo ${fakes.github})`,
];

test('scan: exit 1 and masked output when secrets exist', () => {
  const dir = tempDir();
  writeSettings(dir, leaky());
  const r = run(['scan'], { cwd: dir });
  assert.equal(r.code, 1);
  assert.match(r.stdout, /permissions\.allow\[1\]/);
  assert.match(r.stdout, /auth-header/);
  assert.match(r.stdout, /ghp_…/);
  for (const v of [fakes.bearer, fakes.github]) {
    assert.ok(!r.stdout.includes(v.slice(5)) && !r.stderr.includes(v.slice(5)), 'full secret leaked');
  }
});

test('scan: exit 0 on a clean file, warnings do not fail unless --strict', () => {
  const dir = tempDir();
  writeSettings(dir, ['Bash(npm test)', 'Bash(git status)', 'Read(~/x)', 'Bash(curl:*)']);
  const r = run(['scan'], { cwd: dir });
  assert.equal(r.code, 0);
  assert.match(r.stdout, /broad-rule|allows curl/);
  assert.equal(run(['scan', '--strict'], { cwd: dir }).code, 1);
});

test('scan: --json is parseable and never contains the secret', () => {
  const dir = tempDir();
  writeSettings(dir, leaky());
  const r = run(['scan', '--json'], { cwd: dir });
  const j = JSON.parse(r.stdout);
  assert.equal(j.summary.secrets, 2);
  assert.ok(!r.stdout.includes(fakes.bearer));
});

test('scan: also reads ~/.claude/settings.json and reports bad JSON with exit 2', () => {
  const home = tempDir();
  const proj = tempDir();
  writeSettings(home, leaky(), { name: 'settings.json' });
  assert.equal(run(['scan'], { cwd: proj, home }).code, 1);
  const bad = path.join(proj, 'bad.json');
  fs.writeFileSync(bad, '{ nope');
  assert.equal(run(['scan', bad], { cwd: proj, home }).code, 2);
  assert.equal(run(['scan', 'missing.json'], { cwd: proj, home }).code, 2);
});

test('fix: removes secret rules, backs up at 0600, keeps formatting and other keys', () => {
  for (const indent of [2, 4, '\t']) {
    const dir = tempDir();
    const file = writeSettings(dir, leaky(), { indent });
    const before = fs.readFileSync(file, 'utf8');
    const state = tempDir();
    const r = run(['fix'], { cwd: dir, state });
    assert.equal(r.code, 0);
    assert.match(r.stdout, /[Rr]otate/);
    assert.match(r.stdout, /git log/);
    const after = JSON.parse(fs.readFileSync(file, 'utf8'));
    assert.deepEqual(after.permissions.allow, ['Bash(npm test)', 'Bash(git status)']);
    assert.deepEqual(after.permissions.deny, ['Read(.env)']);
    assert.equal(after.model, 'opus');
    assert.deepEqual(after.env, { KEEP: 'me' });
    const expected = JSON.stringify(
      { ...JSON.parse(before), permissions: { allow: ['Bash(npm test)', 'Bash(git status)'], deny: ['Read(.env)'] } },
      null,
      indent,
    );
    assert.equal(fs.readFileSync(file, 'utf8'), expected + '\n');
    assert.deepEqual(fs.readdirSync(path.dirname(file)), [path.basename(file)], 'no backup next to the file');
    const bdir = path.join(state, 'allowlist-guard', 'backups');
    const baks = fs.readdirSync(bdir);
    assert.equal(baks.length, 1);
    assert.ok(r.stdout.includes(path.join(bdir, baks[0])), 'backup path printed');
    assert.equal(fs.statSync(bdir).mode & 0o777, 0o700);
    const bak = path.join(bdir, baks[0]);
    assert.equal(fs.statSync(bak).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(bak, 'utf8'), before);
    assert.equal(run(['scan'], { cwd: dir }).code, 0);
  }
});

test('fix: --rewrite turns a secret rule into a prefix rule; --dry-run changes nothing', () => {
  const dir = tempDir();
  const file = writeSettings(dir, leaky());
  const before = fs.readFileSync(file, 'utf8');
  run(['fix', '--dry-run', '--rewrite'], { cwd: dir });
  assert.equal(fs.readFileSync(file, 'utf8'), before);
  run(['fix', '--rewrite'], { cwd: dir });
  const allow = JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow;
  assert.ok(allow.includes('Bash(curl:*)'));
  assert.ok(!allow.some((r) => r.includes(fakes.bearer)));
});

test('fix: leaves low-confidence findings unless --include-low', () => {
  const dir = tempDir();
  const file = writeSettings(dir, [`Bash(run ${fakes.entropy})`]);
  run(['fix'], { cwd: dir });
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow.length, 1);
  run(['fix', '--include-low'], { cwd: dir });
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).permissions.allow.length, 0);
});

test('usage errors exit 2', () => {
  assert.equal(run([]).code, 2);
  assert.equal(run(['nope']).code, 2);
  assert.equal(run(['scan', '--bogus'], { cwd: tempDir() }).code, 2);
});

const git = (cwd, ...a) => execFileSync('git', a, { cwd, encoding: 'utf8' });

test('install-hook never overwrites, and the hook blocks staged secrets', () => {
  const dir = tempDir();
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 't@t.test');
  git(dir, 'config', 'user.name', 't');
  const r1 = run(['install-hook'], { cwd: dir });
  assert.equal(r1.code, 0);
  const hook = path.join(dir, '.git', 'hooks', 'pre-commit');
  assert.ok(fs.statSync(hook).mode & 0o100);
  assert.equal(run(['install-hook'], { cwd: dir }).code, 0);

  // make the hook find our binary
  const binDir = tempDir();
  fs.symlinkSync(path.join(ROOT, 'bin/allowlist-guard.js'), path.join(binDir, 'allowlist-guard'));
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}`, HOME: dir };
  const commit = () => {
    try {
      execFileSync('git', ['commit', '-q', '-m', 'x'], { cwd: dir, env, stdio: 'pipe' });
      return 0;
    } catch (e) {
      return e.status;
    }
  };
  writeSettings(dir, leaky());
  git(dir, 'add', '-f', '.claude/settings.local.json');
  assert.notEqual(commit(), 0, 'commit with secret must be blocked');
  writeSettings(dir, ['Bash(npm test)']);
  git(dir, 'add', '-f', '.claude/settings.local.json');
  assert.equal(commit(), 0, 'clean commit must pass');
});

test('install-hook does not touch an existing foreign hook', () => {
  const dir = tempDir();
  git(dir, 'init', '-q');
  const hook = path.join(dir, '.git', 'hooks', 'pre-commit');
  fs.mkdirSync(path.dirname(hook), { recursive: true });
  fs.writeFileSync(hook, '#!/bin/sh\necho mine\n');
  const r = run(['install-hook'], { cwd: dir });
  assert.equal(r.code, 0);
  assert.match(r.stdout, /allowlist-guard scan --staged/);
  assert.equal(fs.readFileSync(hook, 'utf8'), '#!/bin/sh\necho mine\n');
});

test('fix --no-backup writes no backup', () => {
  const dir = tempDir();
  const state = tempDir();
  writeSettings(dir, leaky());
  assert.equal(run(['fix', '--no-backup'], { cwd: dir, state }).code, 0);
  assert.ok(!fs.existsSync(path.join(state, 'allowlist-guard')));
});

test('loopback URL credentials are low severity; remote hosts still fail, even with default credentials', () => {
  const pw = fakes.password;
  const dir = tempDir();
  writeSettings(dir, [
    'Bash(psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres")',
    `Bash(psql "postgresql://app:${pw}@localhost/db")`,
    `Bash(psql "postgresql://app:${pw}@[::1]/db")`,
  ]);
  const r = run(['scan'], { cwd: dir });
  assert.equal(r.code, 0);
  assert.match(r.stdout, /local-dev-credential/);
  assert.equal(run(['scan', '--include-low'], { cwd: dir }).code, 1);

  const remote = tempDir();
  writeSettings(remote, [`Bash(psql "postgresql://app:${pw}@db.example.com/db")`]);
  assert.equal(run(['scan'], { cwd: remote }).code, 1);
  const remoteDefault = tempDir();
  writeSettings(remoteDefault, [`Bash(psql "postgresql://postgres:postgres@db.example.com/db")`]);
  assert.equal(run(['scan'], { cwd: remoteDefault }).code, 1);
});
