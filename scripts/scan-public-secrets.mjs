#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';

const target = path.resolve(process.argv[2] ?? '/tmp/actionproxy-public-export');
const maxFileBytes = 2 * 1024 * 1024;

const ignoredDirectories = new Set([
  '.git',
  'coverage',
  'dist',
  'dist-ssr',
  'node_modules',
  'playwright-report',
  'test-results',
]);

const ignoredFiles = new Set([
  'pnpm-lock.yaml',
  'scripts/scan-public-secrets.mjs',
]);

const scannedExtensions = new Set([
  '',
  '.css',
  '.env',
  '.example',
  '.html',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.sh',
  '.sql',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);

const lineRules = [
  {
    id: 'private-key-block',
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
    reason: 'private key material',
  },
  {
    id: 'aws-access-key-id',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    reason: 'AWS access key id',
  },
  {
    id: 'github-token',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{80,})\b/g,
    reason: 'GitHub token',
  },
  {
    id: 'openai-or-anthropic-key',
    pattern: /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b/g,
    reason: 'OpenAI/Anthropic-style API key',
  },
  {
    id: 'google-api-key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    reason: 'Google API key',
  },
  {
    id: 'slack-token',
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    reason: 'Slack token',
  },
  {
    id: 'stripe-live-key',
    pattern: /\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g,
    reason: 'Stripe live key',
  },
  {
    id: 'npm-token',
    pattern: /\bnpm_[A-Za-z0-9]{36,}\b/g,
    reason: 'npm token',
  },
  {
    id: 'resend-api-key',
    pattern: /\bre_[A-Za-z0-9]{20,}\b/g,
    reason: 'Resend API key',
  },
  {
    id: 'mailgun-api-key',
    pattern: /\bkey-[0-9a-f]{32}\b/gi,
    reason: 'Mailgun API key',
  },
  {
    id: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/g,
    reason: 'JWT-like bearer token',
  },
];

const secretNameFragment =
  '(?:api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret|signing[_-]?secret|webhook[_-]?secret|access[_-]?token|refresh[_-]?token)';
const envSecretNameFragment =
  '(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|SIGNING[_-]?SECRET|WEBHOOK[_-]?SECRET|ACCESS[_-]?TOKEN|REFRESH[_-]?TOKEN)';

const envAssignmentPattern = new RegExp(
  `^\\s*(?:export\\s+)?([A-Z_][A-Z0-9_.-]*${envSecretNameFragment}[A-Z0-9_.-]*)\\s*=\\s*([^\\s#]+)?`,
);

const quotedAssignmentPattern = new RegExp(
  `(?:^|[\\s"'\\\`{,])([A-Za-z0-9_.-]*${secretNameFragment}[A-Za-z0-9_.-]*)\\s*[:=]\\s*(["'])([^"']+)\\2`,
  'gi',
);

const credentialUrlPattern = /\b[a-z][a-z0-9+.-]*:\/\/([^/\s:@]+):([^@\s/]+)@([^\s/]+)/gi;

const findings = [];

if (!(await exists(target))) {
  fail(`Secret scan target does not exist: ${target}`);
}

for await (const relativeFile of walk(target)) {
  if (!shouldScan(relativeFile)) continue;
  const absolutePath = path.join(target, relativeFile);
  const stats = await fs.stat(absolutePath);
  if (stats.size > maxFileBytes) continue;

  const body = await fs.readFile(absolutePath, 'utf8');
  scanFile(relativeFile, body);
}

if (findings.length) {
  console.error(`Public secret scan failed: ${findings.length} finding${findings.length === 1 ? '' : 's'}`);
  for (const finding of findings.slice(0, 80)) {
    console.error(`- ${finding.file}:${finding.line} [${finding.rule}] ${finding.reason}: ${finding.preview}`);
  }
  if (findings.length > 80) {
    console.error(`- ... ${findings.length - 80} additional findings omitted`);
  }
  process.exit(1);
}

console.log(`Public secret scan passed: ${target}`);

function scanFile(relativeFile, body) {
  const lines = body.split(/\r?\n/);
  let allowNextLine = false;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const lineNumber = index + 1;
    const allowsLine = line.includes('public-secret-scan: allow');
    const skipLine = allowsLine || allowNextLine;
    allowNextLine = line.includes('public-secret-scan: allow-next-line');
    if (skipLine) continue;

    for (const rule of lineRules) {
      rule.pattern.lastIndex = 0;
      for (const match of line.matchAll(rule.pattern)) {
        const value = match[0];
        if (isPlaceholderValue(value)) continue;
        addFinding(relativeFile, lineNumber, rule.id, rule.reason, value);
      }
    }

    const envAssignment = envAssignmentPattern.exec(line);
    if (envAssignment) {
      scanAssignedValue(relativeFile, lineNumber, envAssignment[1], envAssignment[2] ?? '');
    }

    quotedAssignmentPattern.lastIndex = 0;
    for (const match of line.matchAll(quotedAssignmentPattern)) {
      scanAssignedValue(relativeFile, lineNumber, match[1], match[3]);
    }

    credentialUrlPattern.lastIndex = 0;
    for (const match of line.matchAll(credentialUrlPattern)) {
      const username = normalizeValue(match[1]);
      const password = normalizeValue(match[2]);
      const host = normalizeValue(match[3]);
      if (isPlaceholderValue(username) && isPlaceholderValue(password)) continue;
      if (isAllowedLocalCredentialUrl(username, password, host)) continue;
      addFinding(relativeFile, lineNumber, 'credential-url', 'URL contains inline credentials', `${username}:${password}@${host}`);
    }
  }
}

function scanAssignedValue(relativeFile, lineNumber, key, rawValue) {
  const value = normalizeValue(rawValue);
  if (!value || isPlaceholderValue(value) || isAllowedTestFixture(relativeFile, value)) return;
  const entropy = shannonEntropy(value);
  const suspiciousLength = value.length >= 16;
  const suspiciousEntropy = value.length >= 12 && entropy >= 3.25;
  if (suspiciousLength || suspiciousEntropy || looksLikeTokenPrefix(value)) {
    addFinding(relativeFile, lineNumber, 'secret-assignment', `non-placeholder value assigned to ${key}`, value);
  }
}

function addFinding(file, line, rule, reason, value) {
  findings.push({
    file,
    line,
    preview: maskValue(value),
    reason,
    rule,
  });
}

async function* walk(directory, base = directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);
    const relativePath = normalizePath(path.relative(base, absolutePath));
    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) continue;
      yield* walk(absolutePath, base);
    } else if (entry.isFile()) {
      yield relativePath;
    }
  }
}

function shouldScan(relativeFile) {
  if (ignoredFiles.has(relativeFile)) return false;
  return scannedExtensions.has(path.extname(relativeFile));
}

function isPlaceholderValue(value) {
  const normalized = normalizeValue(value);
  if (!normalized) return true;
  const lower = normalized.toLowerCase();
  if (lower === 'true' || lower === 'false' || lower === 'null' || lower === 'undefined') return true;
  if (lower === 'none' || lower === 'mock' || lower === 'memory' || lower === 'outbox') return true;
  if (lower === 'platform' || lower === 'community' || lower === 'disabled' || lower === 'managed') return true;
  if (lower === 'api_key' || lower === 'oidc_jwt') return true;
  if (lower.includes('example') || lower.includes('placeholder') || lower.includes('changeme')) return true;
  if (lower.includes('replace-with') || lower.includes('your-') || lower.includes('your_')) return true;
  if (lower.includes('dummy') || lower.includes('fake') || lower.includes('test') || lower.includes('demo')) return true;
  if (lower.includes('local') || lower.includes('actionproxy') || lower.includes('dev-')) return true;
  if (lower === '...' || lower.endsWith('...') || lower.includes('<') || lower.includes('>')) return true;
  if (/^\$\{[A-Za-z0-9_:-]+\}$/.test(normalized)) return true;
  if (/^[xX*._-]{3,}$/.test(normalized)) return true;
  if (
    normalized.length >= 8 &&
    normalized.length % 2 === 0 &&
    normalized.slice(0, normalized.length / 2) ===
      normalized.slice(normalized.length / 2)
  ) return true;
  return false;
}

function isAllowedTestFixture(relativeFile, value) {
  const lowerFile = relativeFile.toLowerCase();
  if (!lowerFile.endsWith('.test.ts') && !lowerFile.endsWith('.test.tsx')) return false;
  return isPlaceholderValue(value) || value.length < 32;
}

function isAllowedLocalCredentialUrl(username, password, host) {
  const lowerHost = host.toLowerCase();
  if (!/^(127\.0\.0\.1|localhost|[^/\s@]*\.example(?:\.com)?)(?::\d+)?(?:\b|$)/.test(lowerHost)) return false;
  return isPlaceholderValue(username) || isPlaceholderValue(password);
}

function looksLikeTokenPrefix(value) {
  return /^(?:sk-|xox|gh[pousr]_|github_pat_|AIza|npm_|re_|key-|sk_live_|rk_live_)/i.test(value);
}

function shannonEntropy(value) {
  const counts = new Map();
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function maskValue(value) {
  const normalized = normalizeValue(value);
  if (normalized.length <= 8) return '<redacted>';
  return `${normalized.slice(0, 4)}...${normalized.slice(-4)}`;
}

function normalizeValue(value) {
  return value.trim().replace(/^["'`]+|["'`,;]+$/g, '');
}

function normalizePath(value) {
  return value.split(path.sep).join('/');
}

async function exists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function fail(message) {
  console.error(message);
  process.exit(1);
}
