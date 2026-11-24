# allowlist-guard

Find and remove secrets that Claude Code saved inside your permission rules.

## The problem

When you answer "Yes, and don't ask again" to a Bash command, Claude Code stores
the whole command as a rule in `.claude/settings.local.json` (or `settings.json`,
or `~/.claude/settings.json`). If the command had a token or password in it,
that value is now sitting in plain text:

```json
"allow": ["Bash(curl -H \"Authorization: Bearer <your token>\" https://api.example.com)"]
```

CSO Online and InfoWorld reported in November 2026 that the "don't ask again"
approvals store commands, secrets included, in settings files that end up in
public repos. GitGuardian, cited by CSO Online, found 31,088 distinct secrets in
`.claude/settings.local.json` files across 23,276 public GitHub repositories, and
5,343 of them were still valid when detected.

- CSO Online: https://www.csoonline.com/article/4247336/claude-codes-dont-ask-again-button-has-a-secrets-spilling-problem.html
- InfoWorld: https://www.infoworld.com/article/4247344/claude-codes-dont-ask-again-button-has-a-secrets-spilling-problem.html

allowlist-guard reads those rule lists, tells you which rules contain secrets,
and can remove them. It has no dependencies and never uses the network.

## 30 seconds

```sh
npx allowlist-guard scan        # project .claude/settings*.json + ~/.claude/settings.json
npx allowlist-guard fix         # remove the rules that contain secrets (backs up first, outside the repo)
npx allowlist-guard install-hook  # block commits that stage a settings file with secrets
```

Example output (secrets are always masked to the first 4 characters):

```
SECRET  .claude/settings.local.json  permissions.allow[7]  auth-header  Umd2…
    Bash(curl -H "Authorization: Bearer Umd2…" https://api.example.com)
warning  .claude/settings.local.json  permissions.allow[9]  allows sudo with any command
    Bash(sudo:*)
```

Then rotate the credential. Removing it from the file does not un-leak it.

Requires Node 18 or newer.

## Commands

`scan [paths...]` checks `permissions.allow`, `permissions.deny` and
`permissions.ask`. A path can be a settings file or a project directory.
Exit code 1 if any high-confidence secret is found, 2 on an unreadable file or bad usage,
0 otherwise. Options: `--json`, `--strict` (broad-rule warnings also exit 1),
`--staged` (check the staged version of settings files in the current repo),
`--include-low` (low-confidence findings also exit 1).

`fix [paths...]` removes every rule with a high-confidence secret.
Before touching a file it copies it to
`${XDG_STATE_HOME:-~/.local/state}/allowlist-guard/backups/` (directory 0700,
file 0600) and prints the path. The backup is kept outside any repo on purpose,
so it cannot be committed. It still contains the secret: delete it once you no
longer need it, or skip it with `--no-backup`.
Indentation, line endings, key order and all other keys are kept.
Options: `--dry-run`, `--no-backup`, `--rewrite` (replace the rule with a prefix like
`Bash(curl:*)` when the command is a single plain binary; this is broader than
what you approved, so it is opt-in), `--include-low` (also remove
low-confidence findings).

`install-hook` adds a `pre-commit` hook that runs `scan --staged`. If a
pre-commit hook already exists it is left alone and the snippet to add is
printed instead.

## What it detects

Secrets (exit code 1):

- Token prefixes: Anthropic `sk-ant-`, OpenAI `sk-` / `sk-proj-`, GitHub
  `ghp_` `gho_` `ghu_` `ghs_` `ghr_` `github_pat_`, AWS `AKIA` / `ASIA`, Slack
  `xox*`, Stripe `sk_live_` / `rk_live_`, Google `AIza`, JWTs.
- `Authorization: Bearer ...` and `Basic ...`, and `x-api-key`-style headers.
- `--password`, `--token`, `--secret`, `--api-key` flags, `mysql -pSECRET`,
  `sshpass -p`, `curl -u user:pass`.
- `password=`, `token=`, `api_key=` and similar assignments.
- URLs with `user:pass@`.
- Low confidence, labeled as such, listed but not failing by default: long
  mixed-case tokens with digits and high entropy, and "local dev credentials"
  (URL passwords on localhost, 127.0.0.0/8, ::1 or 0.0.0.0, or defaults such as
  `postgres:postgres`). `scan --include-low` fails on them and `fix` leaves them
  alone unless you pass `--include-low`.

Values that start with `$`, `<`, `{` or `*` (`$TOKEN`, `<token>`) are treated as
placeholders and ignored.

Warnings (not secrets, exit code unchanged unless `--strict`): `Bash`,
`Bash(*)`, `Bash(rm:*)`, `Bash(curl:*)` with no host, `Bash(sudo:*)`.

## What it does not do

- It does not rotate or revoke keys. Do that at the provider.
- It does not scan git history. After `fix`, search it yourself, for example
  `git log --all --oneline -p -S'<first characters of the secret>' -- .claude/settings.local.json`.
- It does not look at `env` blocks, hooks, MCP server configs, `~/.claude.json`
  or session transcripts, only permission rules.
- It does not find every secret. Unusual formats and short passwords can slip
  through,.

## Tests

```sh
npm test
```

Test secrets are built at runtime, so no real-looking keys are committed.

## License

MIT
