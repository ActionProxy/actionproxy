import type {
  ContentInfluenceEvaluation,
  ContentInfluenceSource,
  PolicyInfluenceGuard,
} from '../policy/policy-types';
import type { ContentExposureRecord, ListContentExposuresResult } from '../storage/store';
import { hashCanonicalJson } from './action-request';

export const CONTENT_INFLUENCE_EVIDENCE_VERSION = 'actionproxy.content-influence.v1' as const;
export const MAX_INFLUENCE_EXPOSURES = 256;
export const MAX_INFLUENCE_SOURCE_REFERENCES = 32;

export interface ContentInfluenceSourceReference {
  integrity: ContentExposureRecord['integrity'];
  sourceId?: string;
  sourceToolCallId: string;
}

export interface ContentInfluenceEvidenceV1 {
  baseDecision: ContentInfluenceEvaluation['baseDecision'];
  bindingHash: string;
  effectiveDecision: ContentInfluenceEvaluation['effectiveDecision'];
  evaluatedAt: string;
  exposureRevision: number;
  exposureSnapshotHash: string;
  influenceScope: {
    id?: string;
    verified: boolean;
  };
  observedSources: ContentInfluenceSource[];
  policy: {
    versionHash: string;
    versionId?: string;
  };
  selectedRule: PolicyInfluenceGuard;
  sourceCount: number;
  sourceCountIsLowerBound: boolean;
  sourceReferences: ContentInfluenceSourceReference[];
  version: typeof CONTENT_INFLUENCE_EVIDENCE_VERSION;
}

export function buildContentInfluenceEvidence(input: {
  evaluatedAt: string;
  evaluation: ContentInfluenceEvaluation;
  exposureLookup?: ListContentExposuresResult;
  influenceScopeId?: string;
  policyVersionHash: string;
  policyVersionId?: string;
  selectedRule: PolicyInfluenceGuard;
}): ContentInfluenceEvidenceV1 {
  const records = sortedRecords(input.exposureLookup?.records ?? []);
  const sourceReferences = records.slice(0, MAX_INFLUENCE_SOURCE_REFERENCES).map((record) => ({
    integrity: record.integrity,
    sourceId: record.sourceId,
    sourceToolCallId: record.sourceToolCallId,
  }));
  const snapshotMaterial = {
    exposureRevision: input.exposureLookup?.revision ?? 0,
    influenceScopeId: input.influenceScopeId ?? null,
    overflow: input.exposureLookup?.overflow ?? false,
    records: records.map((record) => ({
      integrity: record.integrity,
      observedAt: record.observedAt,
      policyVersionHash: record.policyVersionHash,
      sourceId: record.sourceId ?? null,
      sourceToolCallId: record.sourceToolCallId,
    })),
    verified: Boolean(input.influenceScopeId),
    version: 'actionproxy.content-exposure-snapshot.v1',
  };
  const core = {
    baseDecision: input.evaluation.baseDecision,
    effectiveDecision: input.evaluation.effectiveDecision,
    exposureRevision: input.exposureLookup?.revision ?? 0,
    exposureSnapshotHash: hashCanonicalJson(snapshotMaterial),
    influenceScope: {
      id: input.influenceScopeId,
      verified: Boolean(input.influenceScopeId),
    },
    observedSources: [...input.evaluation.observedSources],
    policy: {
      versionHash: input.policyVersionHash,
      versionId: input.policyVersionId,
    },
    selectedRule: {
      allowFrom: [...input.selectedRule.allowFrom],
      otherwise: input.selectedRule.otherwise,
    },
    sourceCount: records.length,
    sourceCountIsLowerBound: input.exposureLookup?.overflow ?? false,
    sourceReferences,
    version: CONTENT_INFLUENCE_EVIDENCE_VERSION,
  };
  return {
    ...core,
    bindingHash: hashCanonicalJson(core),
    evaluatedAt: input.evaluatedAt,
  };
}

export function sameContentInfluenceBinding(
  left: ContentInfluenceEvidenceV1 | undefined,
  right: ContentInfluenceEvidenceV1,
): boolean {
  return Boolean(
    left &&
    validContentInfluenceBindingHash(left) !== undefined &&
    validContentInfluenceBindingHash(right) !== undefined &&
    left.bindingHash === right.bindingHash,
  );
}

export function validContentInfluenceBindingHash(
  evidence: ContentInfluenceEvidenceV1 | undefined,
): string | undefined {
  if (
    !evidence ||
    evidence.version !== CONTENT_INFLUENCE_EVIDENCE_VERSION ||
    !Number.isInteger(evidence.exposureRevision) ||
    evidence.exposureRevision < 0 ||
    evidence.influenceScope.verified !== Boolean(evidence.influenceScope.id) ||
    (evidence.influenceScope.id !== undefined && !/^influence_[a-f0-9]{64}$/u.test(evidence.influenceScope.id))
  ) return undefined;
  try {
    const computed = hashCanonicalJson(contentInfluenceBindingCore(evidence));
    return computed === evidence.bindingHash ? computed : undefined;
  } catch {
    return undefined;
  }
}

export function validatedContentExposureRevisionGuard(
  evidence: ContentInfluenceEvidenceV1 | undefined,
  authoritativeInfluenceScopeId: string | undefined,
): { influenceScopeId: string; revision: number } | undefined {
  if (
    !authoritativeInfluenceScopeId ||
    validContentInfluenceBindingHash(evidence) === undefined ||
    evidence?.influenceScope.verified !== true ||
    evidence.influenceScope.id !== authoritativeInfluenceScopeId ||
    !Number.isInteger(evidence.exposureRevision) ||
    evidence.exposureRevision < 0
  ) {
    return undefined;
  }
  return { influenceScopeId: authoritativeInfluenceScopeId, revision: evidence.exposureRevision };
}

function sortedRecords(records: readonly ContentExposureRecord[]): ContentExposureRecord[] {
  return [...records].sort((left, right) =>
    left.sourceToolCallId.localeCompare(right.sourceToolCallId) || left.observedAt.localeCompare(right.observedAt));
}

function contentInfluenceBindingCore(evidence: ContentInfluenceEvidenceV1) {
  return {
    baseDecision: evidence.baseDecision,
    effectiveDecision: evidence.effectiveDecision,
    exposureRevision: evidence.exposureRevision,
    exposureSnapshotHash: evidence.exposureSnapshotHash,
    influenceScope: {
      id: evidence.influenceScope.id,
      verified: evidence.influenceScope.verified,
    },
    observedSources: [...evidence.observedSources],
    policy: {
      versionHash: evidence.policy.versionHash,
      versionId: evidence.policy.versionId,
    },
    selectedRule: {
      allowFrom: [...evidence.selectedRule.allowFrom],
      otherwise: evidence.selectedRule.otherwise,
    },
    sourceCount: evidence.sourceCount,
    sourceCountIsLowerBound: evidence.sourceCountIsLowerBound,
    sourceReferences: evidence.sourceReferences.map((reference) => ({
      integrity: reference.integrity,
      sourceId: reference.sourceId,
      sourceToolCallId: reference.sourceToolCallId,
    })),
    version: evidence.version,
  };
}
