import fs from 'node:fs';
import { detectSecrets, redact, mask, broadRule } from './detect.js';
import { loadSettings, parseSettings, rulesOf } from './settings.js';

const clip = (s) => (s.length > 100 ? s.slice(0, 97) + '...' : s);

/** Scan one parsed settings object. Never returns a full secret. */
export function scanData(data, file) {
  const findings = [];
  const warnings = [];
  for (const { list, index, rule } of rulesOf(data)) {
    const secrets = detectSecrets(rule);
    const ref = { file, list: `permissions.${list}`, index };
    if (secrets.length) {
      const shown = redact(rule, secrets);
      for (const s of secrets) {
        findings.push({
          ...ref,
          type: s.type,
          confidence: s.confidence,
          masked: mask(s.value),
          rule: clip(shown),
        });
      }
    }
    if (list === 'allow') {
      const reason = broadRule(rule);
      if (reason) warnings.push({ ...ref, type: 'broad-rule', reason, rule: clip(rule) });
    }
  }
  return { findings, warnings };
}

/**
 * @param {{file:string, text?:string}[]} sources  text is read from disk when omitted
 */
export function scanFiles(sources) {
  const result = { files: [], findings: [], warnings: [], errors: [] };
  for (const { file, text, display = file } of sources) {
    try {
      const { data } = text === undefined ? loadSettings(file) : parseSettings(text);
      const r = scanData(data, display);
      result.files.push(display);
      result.findings.push(...r.findings);
      result.warnings.push(...r.warnings);
    } catch (e) {
      const msg = e.code === 'ENOENT' ? 'file not found' : e.message;
      result.errors.push({ file: display, error: msg });
    }
  }
  return result;
}

export function exists(file) {
  return fs.existsSync(file);
}
