import { discover } from './settings.js';
import { scanFiles } from './scan.js';
import { fixFile } from './fix.js';
import { installHook, stagedSources, SNIPPET } from './hook.js';

const HELP = `allowlist-guard - find secrets saved in Claude Code permission rules

Usage:
  allowlist-guard scan [paths...] [--json] [--strict] [--staged]
  allowlist-guard fix [paths...] [--rewrite] [--include-low] [--dry-run]
  allowlist-guard install-hook

Default paths: ./.claude/settings*.json and ~/.claude/settings.json
A directory path means <dir>/.claude/settings*.json.

Exit codes: 0 clean, 1 secrets found, 2 error (unreadable file, bad usage).
--strict also exits 1 when broad-rule warnings exist.
`;

const out = (s) => process.stdout.write(s + '\n');
const err = (s) => process.stderr.write(s + '\n');

function parseArgs(argv) {
  const flags = new Set();
  const paths = [];
  for (const a of argv) {
    if (a.startsWith('--')) flags.add(a);
    else paths.push(a);
  }
  return { flags, paths };
}

function checkFlags(flags, allowed) {
  for (const f of flags) if (!allowed.includes(f)) throw new Error(`unknown option ${f}`);
}

function printScan(r) {
  for (const f of r.findings) {
    const tag = f.confidence === 'low' ? 'LOW-CONFIDENCE' : 'SECRET';
    out(`${tag}  ${f.file}  ${f.list}[${f.index}]  ${f.type}  ${f.masked}`);
    out(`    ${f.rule}`);
  }
  for (const w of r.warnings) {
    out(`warning  ${w.file}  ${w.list}[${w.index}]  ${w.reason}`);
    out(`    ${w.rule}`);
  }
  for (const e of r.errors) err(`error  ${e.file}: ${e.error}`);
  const high = r.findings.filter((f) => f.confidence === 'high').length;
  const low = r.findings.length - high;
  out(
    `\n${r.files.length} file(s) scanned: ${high} secret(s), ${low} low-confidence, ${r.warnings.length} broad-rule warning(s).`,
  );
  if (r.findings.length) out('Run "allowlist-guard fix" to remove them, then rotate the credentials.');
}

function cmdScan(argv) {
  const { flags, paths } = parseArgs(argv);
  checkFlags(flags, ['--json', '--strict', '--staged']);
  const sources = flags.has('--staged')
    ? stagedSources(process.cwd())
    : discover(paths).map((file) => ({ file }));
  const r = scanFiles(sources);
  if (flags.has('--json')) {
    const high = r.findings.filter((f) => f.confidence === 'high').length;
    out(
      JSON.stringify(
        { ...r, summary: { secrets: high, lowConfidence: r.findings.length - high, warnings: r.warnings.length } },
        null,
        2,
      ),
    );
  } else printScan(r);
  if (r.findings.length) return 1;
  if (flags.has('--strict') && r.warnings.length) return 1;
  return r.errors.length ? 2 : 0;
}

function cmdFix(argv) {
  const { flags, paths } = parseArgs(argv);
  checkFlags(flags, ['--rewrite', '--include-low', '--dry-run']);
  const opts = {
    rewrite: flags.has('--rewrite'),
    includeLow: flags.has('--include-low'),
    dryRun: flags.has('--dry-run'),
  };
  let changed = 0;
  let failed = false;
  for (const file of discover(paths)) {
    try {
      const r = fixFile(file, opts);
      if (!r.removed && !r.rewritten) continue;
      changed++;
      const verb = opts.dryRun ? 'would change' : 'changed';
      out(`${verb} ${file}: ${r.removed} rule(s) removed, ${r.rewritten} rewritten to a prefix`);
      if (r.backup) out(`  backup (0600, still contains the secrets): ${r.backup}`);
    } catch (e) {
      failed = true;
      err(`error  ${file}: ${e.code === 'ENOENT' ? 'file not found' : e.message}`);
    }
  }
  if (!changed) out('No rules with secrets found.');
  else {
    out(`
Rotate every credential that was in those rules. Removing it from the file does not un-leak it.
Delete the .bak file(s) once you no longer need them, and do not commit them.
Check git history for copies:
  git log --all --oneline -p -S'<first characters of the secret>' -- <settings file>`);
    if (opts.rewrite) out('Note: --rewrite grants every use of that command, which is broader than the original rule.');
  }
  return failed ? 2 : 0;
}

function cmdInstallHook() {
  let r;
  try {
    r = installHook(process.cwd());
  } catch {
    err('error: not inside a git repository');
    return 2;
  }
  if (r.status === 'created') out(`Installed ${r.path}`);
  else if (r.status === 'already-installed') out(`Already installed in ${r.path}`);
  else out(`A pre-commit hook already exists at ${r.path}. Not touching it.\nAdd this to it:\n\n${SNIPPET}`);
  return 0;
}

export function main(argv) {
  const [cmd, ...rest] = argv;
  try {
    if (!cmd || cmd === '--help' || cmd === '-h' || cmd === 'help') {
      out(HELP);
      return cmd ? 0 : 2;
    }
    if (cmd === '--version') {
      out('0.1.0');
      return 0;
    }
    if (cmd === 'scan') return cmdScan(rest);
    if (cmd === 'fix') return cmdFix(rest);
    if (cmd === 'install-hook') return cmdInstallHook();
    err(`unknown command: ${cmd}\n`);
    err(HELP);
    return 2;
  } catch (e) {
    err(`error: ${e.message}`);
    return 2;
  }
}
