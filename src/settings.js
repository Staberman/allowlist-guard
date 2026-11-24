import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const LISTS = ['allow', 'deny', 'ask'];

function settingsIn(dir) {
  try {
    return fs
      .readdirSync(dir)
      .filter((n) => /^settings.*\.json$/.test(n))
      .sort()
      .map((n) => path.join(dir, n));
  } catch {
    return [];
  }
}

/** Resolve CLI path arguments (or the defaults) to a de-duplicated file list. */
export function discover(args, cwd = process.cwd()) {
  const out = [];
  if (args.length === 0) {
    out.push(...settingsIn(path.join(cwd, '.claude')));
    const home = path.join(os.homedir(), '.claude', 'settings.json');
    if (fs.existsSync(home)) out.push(home);
  } else {
    for (const a of args) {
      const p = path.resolve(cwd, a);
      let st;
      try {
        st = fs.statSync(p);
      } catch {
        out.push(p); // surfaces as a read error later
        continue;
      }
      if (st.isDirectory()) {
        const claudeDir = path.basename(p) === '.claude' ? p : path.join(p, '.claude');
        out.push(...settingsIn(claudeDir));
      } else out.push(p);
    }
  }
  const seen = new Set();
  return out.filter((p) => {
    let key = p;
    try {
      key = fs.realpathSync(p);
    } catch {}
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function detectIndent(raw) {
  const m = raw.match(/\n([ \t]+)\S/);
  if (!m) return raw.includes('\n') ? 2 : 0;
  return m[1][0] === '\t' ? '\t' : m[1].length;
}

/** Parse settings text, remembering the formatting needed to write it back. */
export function parseSettings(text) {
  const bom = text.charCodeAt(0) === 0xfeff;
  const raw = bom ? text.slice(1) : text;
  const data = JSON.parse(raw);
  if (data === null || typeof data !== 'object' || Array.isArray(data)) {
    throw new Error('top level is not a JSON object');
  }
  return {
    data,
    format: {
      bom,
      indent: detectIndent(raw),
      eol: raw.includes('\r\n') ? '\r\n' : '\n',
      finalNewline: /\n$/.test(raw),
    },
  };
}

export function loadSettings(file) {
  return parseSettings(fs.readFileSync(file, 'utf8'));
}

export function serialize(data, format) {
  let text = JSON.stringify(data, null, format.indent);
  if (format.eol === '\r\n') text = text.replace(/\n/g, '\r\n');
  if (format.finalNewline) text += format.eol;
  return (format.bom ? '﻿' : '') + text;
}

/** Yields { list, index, rule } for every string rule under permissions. */
export function* rulesOf(data) {
  const perms = data && data.permissions;
  if (!perms || typeof perms !== 'object') return;
  for (const list of LISTS) {
    if (!Array.isArray(perms[list])) continue;
    for (let index = 0; index < perms[list].length; index++) {
      const rule = perms[list][index];
      if (typeof rule === 'string') yield { list, index, rule };
    }
  }
}
