import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Fake secrets are assembled at runtime so no real-looking key is committed.
const rnd = (seed, n) => crypto.createHash('sha512').update(seed).digest('base64url').slice(0, n);
const alnum = (seed, n) => rnd(seed, n * 2).replace(/[-_]/g, 'q').slice(0, n);

export const fakes = {
  anthropic: ['sk', 'ant', 'api03'].join('-') + '-' + rnd('a', 40),
  openai: 'sk' + '-proj-' + rnd('o', 40),
  github: 'gh' + 'p_' + alnum('g', 36),
  aws: 'AK' + 'IA' + 'ABCDEFGHIJKLMNOP',
  slack: 'xo' + 'xb-' + '1234567890-' + alnum('s', 24),
  stripe: 'sk_' + 'live_' + alnum('st', 24),
  google: 'AI' + 'za' + alnum('go', 35),
  jwt: ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiIxMjM0NTY3ODkwIn0', alnum('j', 22)].join('.'),
  bearer: alnum('b', 30),
  password: 'hunter' + alnum('p', 8),
  entropy: alnum('e', 12) + 'Xy9Q' + alnum('e2', 14),
};

export function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'alg-'));
}

export function writeSettings(dir, rules, { indent = 2, name = 'settings.local.json', lists } = {}) {
  const file = path.join(dir, '.claude', name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const data = {
    model: 'opus',
    permissions: lists || { allow: rules, deny: ['Read(.env)'] },
    env: { KEEP: 'me' },
  };
  fs.writeFileSync(file, JSON.stringify(data, null, indent) + '\n');
  return file;
}

const BIN = path.join(ROOT, 'bin/allowlist-guard.js');

export function run(args, { cwd, home } = {}) {
  const r = spawnSync(process.execPath, [BIN, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, HOME: home || cwd || os.tmpdir() },
  });
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}
