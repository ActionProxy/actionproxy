import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const blockedSeverities = new Set(['critical', 'high']);

function advisoryId(advisory) {
  return advisory.github_advisory_id ?? String(advisory.id ?? '');
}

function isDate(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

export function validateDependencyAudit(report, reviewDocument, today = new Date().toISOString().slice(0, 10)) {
  if (!report || typeof report !== 'object' || Array.isArray(report) || !report.advisories || typeof report.advisories !== 'object') {
    throw new Error('pnpm returned an invalid dependency audit report.');
  }
  if (!reviewDocument || !Array.isArray(reviewDocument.reviews)) {
    throw new Error('Dependency audit review file must contain a reviews array.');
  }

  const advisories = Object.values(report.advisories);
  const blocked = advisories.filter((advisory) => blockedSeverities.has(advisory?.severity));
  if (blocked.length > 0) {
    throw new Error(`Blocked dependency advisories: ${blocked.map(advisoryId).sort().join(', ')}`);
  }

  const moderate = new Map(
    advisories.filter((advisory) => advisory?.severity === 'moderate').map((advisory) => [advisoryId(advisory), advisory]),
  );
  const reviews = new Map();
  for (const review of reviewDocument.reviews) {
    if (!review || typeof review.advisoryId !== 'string' || !/^GHSA-[a-z0-9-]+$/i.test(review.advisoryId)) {
      throw new Error('Every dependency review requires a GitHub advisoryId.');
    }
    if (reviews.has(review.advisoryId)) throw new Error(`Duplicate dependency review: ${review.advisoryId}`);
    if (typeof review.reviewedBy !== 'string' || review.reviewedBy.trim().length < 2) {
      throw new Error(`Dependency review ${review.advisoryId} requires reviewedBy.`);
    }
    if (!isDate(review.reviewedOn) || !isDate(review.expiresOn)) {
      throw new Error(`Dependency review ${review.advisoryId} requires reviewedOn and expiresOn dates.`);
    }
    if (review.reviewedOn > today || review.expiresOn < today) {
      throw new Error(`Dependency review ${review.advisoryId} is not valid on ${today}.`);
    }
    if (typeof review.rationale !== 'string' || review.rationale.trim().length < 40) {
      throw new Error(`Dependency review ${review.advisoryId} requires a substantive rationale.`);
    }
    reviews.set(review.advisoryId, review);
  }

  const missing = [...moderate.keys()].filter((id) => !reviews.has(id));
  if (missing.length > 0) throw new Error(`Moderate advisories without written review: ${missing.sort().join(', ')}`);
  const unused = [...reviews.keys()].filter((id) => !moderate.has(id));
  if (unused.length > 0) throw new Error(`Dependency reviews no longer match the audit: ${unused.sort().join(', ')}`);

  return { advisories: advisories.length, moderateReviewed: moderate.size };
}

function main() {
  const result = spawnSync('corepack', ['pnpm', 'audit', '--json'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    shell: process.platform === 'win32',
  });
  if (result.error) throw result.error;

  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error(result.stderr.trim() || 'pnpm audit did not return valid JSON.');
  }
  const reviewPath = process.argv[2] ?? 'docs/dependency-audit-reviews.json';
  const reviews = JSON.parse(readFileSync(reviewPath, 'utf8'));
  const summary = validateDependencyAudit(report, reviews);
  console.log(
    `Dependency audit passed: ${summary.advisories} advisories, ${summary.moderateReviewed} moderate reviews.`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
