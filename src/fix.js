import fs from 'node:fs';
import { detectSecrets, broadRule } from './detect.js';
import { loadSettings, serialize, LISTS } from './settings.js';

const SHELLS = new Set(['bash', 'sh', 'zsh', 'env', 'eval', 'xargs', 'sudo', 'exec', 'ssh', 'nohup', 'time']);

/** "Bash(curl -H x https://h)" -> "Bash(curl:*)" when the command is a single plain binary. */
export function safePrefix(rule) {
  const m = rule.match(/^Bash\(\s*([A-Za-z][\w.+-]*)\s[\s\S]*\)$/);
  if (!m || SHELLS.has(m[1])) return null;
  if (/[|;&`$<>\n]|\$\(/.test(rule)) return null;
  return `Bash(${m[1]}:*)`;
}

function backupName(file) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  return `${file}.${stamp}.bak`;
}

/**
 * Remove (or rewrite) rules containing secrets.
 * @returns {{file, removed:number, rewritten:number, backup:string|null}}
 */
export function fixFile(file, { rewrite = false, includeLow = false, dryRun = false } = {}) {
  const { data, format } = loadSettings(file);
  const perms = data.permissions;
  const out = { file, removed: 0, rewritten: 0, backup: null };
  if (!perms || typeof perms !== 'object') return out;

  for (const list of LISTS) {
    if (!Array.isArray(perms[list])) continue;
    const next = [];
    for (const rule of perms[list]) {
      const hits =
        typeof rule === 'string'
          ? detectSecrets(rule).filter((s) => includeLow || s.confidence === 'high')
          : [];
      if (!hits.length) {
        next.push(rule);
        continue;
      }
      const prefix = rewrite && list === 'allow' ? safePrefix(rule) : null;
      if (prefix && !detectSecrets(prefix).length && !next.includes(prefix) && !perms[list].includes(prefix)) {
        next.push(prefix);
        out.rewritten++;
      } else out.removed++;
    }
    perms[list] = next;
  }
  if (!out.removed && !out.rewritten) return out;
  if (dryRun) return out;

  const original = fs.readFileSync(file);
  const mode = fs.statSync(file).mode & 0o777;
  out.backup = backupName(file);
  fs.writeFileSync(out.backup, original, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(out.backup, 0o600);

  const tmp = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, serialize(data, format), { mode });
  fs.renameSync(tmp, file);
  return out;
}

export { broadRule };
