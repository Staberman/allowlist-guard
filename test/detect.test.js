import test from 'node:test';
import assert from 'node:assert/strict';
import { detectSecrets, mask, redact, broadRule } from '../src/detect.js';
import { fakes } from './helpers.js';

const types = (rule) => detectSecrets(rule).map((f) => f.type);

test('known token prefixes are detected', () => {
  const cases = [
    ['anthropic', 'anthropic-key'],
    ['openai', 'openai-key'],
    ['github', 'github-token'],
    ['aws', 'aws-access-key'],
    ['slack', 'slack-token'],
    ['stripe', 'stripe-key'],
    ['google', 'google-api-key'],
    ['jwt', 'jwt'],
  ];
  for (const [k, type] of cases) {
    assert.deepEqual(types(`Bash(curl -H "x: ${fakes[k]}" https://h.test)`), [type], k);
  }
});

test('anthropic keys are not double-reported as openai keys', () => {
  assert.deepEqual(types(`Bash(echo ${fakes.anthropic})`), ['anthropic-key']);
});

test('authorization headers, flags, assignments and url credentials', () => {
  assert.deepEqual(types(`Bash(curl -H "Authorization: Bearer ${fakes.bearer}" https://h.test)`), ['auth-header']);
  assert.deepEqual(types(`Bash(curl -H 'Authorization: Basic ${fakes.bearer}==' https://h.test)`), ['auth-header']);
  assert.deepEqual(types(`Bash(tool --password ${fakes.password})`), ['password-flag']);
  assert.deepEqual(types(`Bash(tool --token=${fakes.password})`), ['password-flag']);
  assert.deepEqual(types(`Bash(mysql -u root -p${fakes.password} db)`), ['password-flag']);
  assert.deepEqual(types(`Bash(curl -u admin:${fakes.password} https://h.test)`), ['basic-auth-flag']);
  assert.deepEqual(types(`Bash(API_KEY=${fakes.password} node x.js)`), ['credential-assignment']);
  assert.deepEqual(types(`Bash(git clone https://user:${fakes.password}@host.test/r.git)`), ['url-credentials']);
});

test('high-entropy fallback is low confidence', () => {
  const f = detectSecrets(`Bash(run ${fakes.entropy})`);
  assert.equal(f.length, 1);
  assert.equal(f[0].type, 'high-entropy-string');
  assert.equal(f[0].confidence, 'low');
});

test('ordinary rules produce no findings', () => {
  const rules = [
    'Bash(npm test)',
    'Bash(git status)',
    'Bash(git log --oneline -n 20)',
    'Read(~/x)',
    'Read(//Users/someone/projects/a-very-long-directory-name-2024-final/src/**)',
    'WebFetch(domain:github.com)',
    'Bash(curl -H "Authorization: Bearer $TOKEN" https://h.test)',
    'Bash(mysql -u root -p mydb)',
    'Bash(mkdir -p build/out)',
    'Bash(docker run -p 8080:80 nginx)',
    'Bash(git show 3f786850e387550fdab836ed7e6dc881de23001b)',
    'mcp__server__tool',
  ];
  for (const r of rules) assert.deepEqual(detectSecrets(r), [], r);
});

test('masking shows at most the first 4 chars and an ellipsis', () => {
  assert.equal(mask(fakes.anthropic), fakes.anthropic.slice(0, 4) + '…');
  assert.equal(mask('ab'), '…');
  const rule = `Bash(curl -H "x: ${fakes.github}")`;
  const shown = redact(rule, detectSecrets(rule));
  assert.ok(!shown.includes(fakes.github.slice(5)));
  assert.ok(shown.includes('ghp_…'));
});

test('broad rules', () => {
  for (const r of ['Bash(*)', 'Bash', 'Bash(rm:*)', 'Bash(curl:*)', 'Bash(sudo:*)', 'Bash(sudo *)']) {
    assert.ok(broadRule(r), r);
  }
  for (const r of ['Bash(npm test)', 'Bash(curl https://api.test:*)', 'Bash(rm build/x)', 'Read(*)']) {
    assert.equal(broadRule(r), null, r);
  }
});

test('redaction targets the secret, not an earlier identical substring', () => {
  const rule = 'Bash(psql "postgresql://postgres:postgres@127.0.0.1/db" -c x)';
  const shown = redact(rule, detectSecrets(rule));
  assert.ok(shown.includes('postgresql://postgres:po…@'), shown);
});
