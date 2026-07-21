import type { JsonObject } from '../models';
import type { PolicyFile } from '../policy/policy-types';

const DEFAULT_SENSITIVE_KEYS = new Set([
  'accesstoken',
  'apikey',
  'apitoken',
  'authorization',
  'bottoken',
  'clientsecret',
  'credential',
  'credentials',
  'password',
  'privatekey',
  'refreshtoken',
  'secret',
  'sessiontoken',
  'signingsecret',
  'token',
  'webhooksecret',
]);

const TOOL_CALL_RESULT_AUTHORIZATION_PATHS = [
  'grant.nonce',
  'grant.signature',
  'receipt.signature',
] as const;

export interface RedactionOptions {
  fields?: string[];
  replacement?: string;
}

export function redactionOptionsFromPolicy(policy: PolicyFile): RedactionOptions {
  const fields = new Set<string>();
  for (const rule of [policy.default, ...Object.values(policy.tools)]) {
    for (const field of rule.redaction?.fields ?? []) fields.add(field);
  }
  return { fields: [...fields], replacement: '[REDACTED]' };
}

export function redactJsonObject(value: JsonObject, options: RedactionOptions = {}): JsonObject {
  return redactValue(value, pathSet(options.fields ?? []), options.replacement ?? '[REDACTED]', []) as JsonObject;
}

export function redactJsonObjectAtPath(
  value: JsonObject,
  rootPath: string,
  options: RedactionOptions = {},
): JsonObject {
  const path = rootPath.split('.').map((part) => part.trim()).filter(Boolean);
  return redactValue(value, pathSet(options.fields ?? []), options.replacement ?? '[REDACTED]', path) as JsonObject;
}

export function redactToolCallResult(value: JsonObject, options: RedactionOptions = {}): JsonObject {
  return redactJsonObject(value, {
    ...options,
    fields: [...new Set([...(options.fields ?? []), ...TOOL_CALL_RESULT_AUTHORIZATION_PATHS])],
  });
}

export function redactReceiptSignature<T extends { signature: string }>(
  receipt: T,
  options: RedactionOptions = {},
): T {
  return { ...receipt, signature: options.replacement ?? '[REDACTED]' };
}

function redactValue(value: unknown, redactedPaths: Set<string>, replacement: string, path: string[]): unknown {
  if (Array.isArray(value)) {
    return value.map((item, index) => redactValue(item, redactedPaths, replacement, [...path, String(index)]));
  }

  if (!isRecord(value)) return value;

  const output: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    const childPath = [...path, key];
    if (shouldRedact(key, childPath, redactedPaths)) {
      output[key] = replacement;
      continue;
    }
    output[key] = redactValue(item, redactedPaths, replacement, childPath);
  }
  return output;
}

function shouldRedact(key: string, path: string[], redactedPaths: Set<string>): boolean {
  const normalizedKey = key.replaceAll(/[-_\s]/g, '').toLowerCase();
  if (DEFAULT_SENSITIVE_KEYS.has(normalizedKey) || DEFAULT_SENSITIVE_KEYS.has(key.toLowerCase())) return true;

  const normalizedPath = path.join('.');
  return redactedPaths.has(normalizedPath);
}

function pathSet(fields: string[]): Set<string> {
  return new Set(fields.map((field) => field.trim()).filter(Boolean));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}
