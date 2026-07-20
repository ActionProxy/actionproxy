import type { ActionReceiptRecord } from '../models';
import { hashJson, hmacSha256Hex, safeEqual, stableStringify } from './crypto';

export const ACTION_RECEIPT_KEY_ID = 'actionproxy-local-hmac-v1';

export function signReceipt(secret: string, record: Omit<ActionReceiptRecord, 'receiptHash' | 'signature'>): ActionReceiptRecord {
  const material = receiptMaterial(record);
  const receiptHash = hashJson(material);
  const signature = hmacSha256Hex(secret, stableStringify({ ...material, receiptHash }));
  return {
    ...record,
    receiptHash,
    signature,
  };
}

export function verifyReceipt(secret: string, record: ActionReceiptRecord): boolean {
  const { receiptHash, signature, ...unsigned } = record;
  const material = receiptMaterial(unsigned);
  const expectedHash = hashJson(material);
  if (!safeEqual(receiptHash, expectedHash)) return false;
  return safeEqual(signature, hmacSha256Hex(secret, stableStringify({ ...material, receiptHash })));
}

function receiptMaterial(record: Omit<ActionReceiptRecord, 'receiptHash' | 'signature'>): Record<string, unknown> {
  return {
    approvalId: record.approvalId,
    approvedEnvelopeHash: record.approvedEnvelopeHash,
    approvedInputHash: record.approvedInputHash,
    createdAt: record.createdAt,
    decisionActor: record.decisionActor,
    decisionAuth: record.decisionAuth,
    decisionKind: record.decisionKind,
    executionMode: record.executionMode,
    expiresAt: record.expiresAt,
    id: record.id,
    issuedAt: record.issuedAt,
    keyId: record.keyId,
    operation: record.operation,
    originalEnvelopeHash: record.originalEnvelopeHash,
    originalInputHash: record.originalInputHash,
    policyDecision: record.policyDecision,
    policyReason: record.policyReason,
    policyRisk: record.policyRisk,
    policyVersionHash: record.policyVersionHash,
    policyVersionId: record.policyVersionId,
    protocol: record.protocol,
    reviewHash: record.reviewHash,
    signatureAlg: record.signatureAlg,
    source: record.source,
    toolCallId: record.toolCallId,
    toolName: record.toolName,
    version: record.version,
    workspaceId: record.workspaceId,
  };
}
