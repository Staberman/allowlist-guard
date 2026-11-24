import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const MARK = '# allowlist-guard';

export const SNIPPET = `${MARK}: block commits that stage Claude Code settings containing secrets
if command -v allowlist-guard >/dev/null 2>&1; then
  allowlist-guard scan --staged || exit 1
elif command -v npx >/dev/null 2>&1; then
  npx --no-install allowlist-guard scan --staged || exit 1
else
  echo "allowlist-guard not found; skipping settings check" >&2
fi
`;

const git = (args, cwd) =>
  execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

export function hookPath(cwd) {
  const p = git(['rev-parse', '--git-path', 'hooks/pre-commit'], cwd);
  return path.resolve(cwd, p);
}

/** @returns {{status:'created'|'exists'|'already-installed', path:string}} */
export function installHook(cwd) {
  const target = hookPath(cwd);
  if (fs.existsSync(target)) {
    const has = fs.readFileSync(target, 'utf8').includes(MARK);
    return { status: has ? 'already-installed' : 'exists', path: target };
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, `#!/bin/sh\n${SNIPPET}`, { mode: 0o755, flag: 'wx' });
  fs.chmodSync(target, 0o755);
  return { status: 'created', path: target };
}

const SETTINGS_RE = /(^|\/)\.claude\/settings[^/]*\.json$/;

/** Staged settings files, read from the index (not the working tree). */
export function stagedSources(cwd) {
  const top = git(['rev-parse', '--show-toplevel'], cwd);
  const names = git(['diff', '--cached', '--name-only', '--diff-filter=ACM', '-z'], top)
    .split('\0')
    .filter((n) => SETTINGS_RE.test(n));
  return names.map((n) => ({
    file: n,
    display: n,
    text: execFileSync('git', ['show', `:${n}`], { cwd: top, encoding: 'utf8' }),
  }));
}
