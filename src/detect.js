// Secret and broad-rule detection for a single permission rule string.
// Pure functions, no I/O.

function isLoopback(host) {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || h === '0.0.0.0' || /^127\.\d+\.\d+\.\d+$/.test(h);
}

// URL credentials on a loopback host are low severity. A remote host is not,
// even with default credentials: a reachable server with a default password is a real leak.
function localDevCredential(m) {
  const host = m[3];
  if (isLoopback(host)) {
    return { type: 'local-dev-credential', confidence: 'low' };
  }
  return null;
}

const PLACEHOLDER = /^(?:[$<{(*%]|\.\.\.|x{3,}|changeme|your[_-]|example|redacted)/i;

// Ordered by confidence. Earlier matches win when ranges overlap.
// `group` is the capture group holding the secret (0 = whole match).
const PATTERNS = [
  { type: 'anthropic-key', re: /sk-ant-[A-Za-z0-9_-]{8,}/g },
  { type: 'openai-key', re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
  { type: 'github-token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g },
  { type: 'aws-access-key', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { type: 'stripe-key', re: /\b[sr]k_live_[A-Za-z0-9]{10,}/g },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{30,}/g },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/g },
  { type: 'auth-header', re: /\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{8,})/gi, group: 1 },
  {
    type: 'api-key-header',
    re: /\b(?:x-api-key|api-key|x-auth-token|x-access-token)\s*:\s*\\?["']?([^\s"'\\]{8,})/gi,
    group: 1,
  },
  {
    type: 'password-flag',
    re: /--(?:password|passwd|token|secret|api-key|apikey|access-token|auth-token)(?:=|\s+)\\?["']?([^\s"'\\][^\s"'\\]*)/gi,
    group: 1,
  },
  {
    type: 'password-flag',
    re: /\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^|;&]*?\s-p([^\s"'\\-][^\s"'\\]{2,})/g,
    group: 1,
  },
  { type: 'password-flag', re: /\bsshpass\s+-p\s*\\?["']?([^\s"'\\]+)/g, group: 1 },
  {
    type: 'basic-auth-flag',
    re: /\bcurl\b[^|;&]*?\s(?:-u|--user)\s+\\?["']?[^\s:"'\\]+:([^\s"'\\]+)/g,
    group: 1,
  },
  {
    type: 'credential-assignment',
    re: /\b(?:password|passwd|pwd|token|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*=\s*\\?["']?([^\s"'\\&;]{4,})/gi,
    group: 1,
  },
  {
    type: 'url-credentials',
    re: /\b[a-z][a-z0-9+.-]*:\/\/([^\s:/@"'\\]+):([^\s@/"'\\]+)@(\[[0-9a-f:]+\]|[^\s:/"'\\?#]+)/gi,
    group: 2,
    classify: localDevCredential,
  },
];

for (const p of PATTERNS) p.re = new RegExp(p.re.source, p.re.flags + 'd');

export function mask(value) {
  const shown = Math.min(4, Math.floor(value.length / 3));
  return value.slice(0, shown) + '…';
}

function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function overlaps(found, start, end) {
  return found.some((f) => start < f.end && end > f.start);
}

/**
 * @returns {{type:string, confidence:'high'|'low', start:number, end:number, value:string}[]}
 */
export function detectSecrets(rule) {
  const found = [];
  for (const { type, re, group = 0, classify } of PATTERNS) {
    for (const m of rule.matchAll(re)) {
      const value = m[group];
      if (!value || PLACEHOLDER.test(value)) continue;
      const start = m.indices[group][0];
      const end = start + value.length;
      if (overlaps(found, start, end)) continue;
      const c = classify ? classify(m) : null;
      found.push({ type: c ? c.type : type, confidence: c ? c.confidence : 'high', start, end, value });
    }
  }
  // Conservative fallback: long mixed-case tokens with digits and high entropy.
  for (const m of rule.matchAll(/[A-Za-z0-9+_=-]{24,}/g)) {
    const value = m[0];
    const start = m.index;
    const end = start + value.length;
    if (overlaps(found, start, end)) continue;
    if (/^[a-z0-9_-]+$/.test(value) || /^[A-Z0-9_-]+$/.test(value)) continue;
    if (!/\d/.test(value) || !/[a-z]/.test(value) || !/[A-Z]/.test(value)) continue;
    if (entropy(value) < 4.0) continue;
    found.push({ type: 'high-entropy-string', confidence: 'low', start, end, value });
  }
  return found.sort((a, b) => a.start - b.start);
}

export function redact(rule, findings) {
  let out = '';
  let pos = 0;
  for (const f of findings) {
    out += rule.slice(pos, f.start) + mask(f.value);
    pos = f.end;
  }
  return out + rule.slice(pos);
}

const BROAD = [
  { re: /^Bash(?:\(\s*(?::?\*)?\s*\))?$/, reason: 'allows every shell command' },
  { re: /^Bash\(\s*rm\s*(?::\*|\s\*)\s*\)$/, reason: 'allows rm with any arguments' },
  { re: /^Bash\(\s*curl\s*(?::\*|\s\*)\s*\)$/, reason: 'allows curl to any host' },
  { re: /^Bash\(\s*sudo\s*(?::\*|\s\*)\s*\)$/, reason: 'allows sudo with any command' },
];

export function broadRule(rule) {
  const r = rule.trim();
  for (const { re, reason } of BROAD) if (re.test(r)) return reason;
  return null;
}
