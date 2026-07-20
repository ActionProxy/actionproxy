import diagnosticsChannel from 'node:diagnostics_channel';
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_INFLUENCE_EXPOSURES } from '../contracts/content-influence';
import { evaluateContentInfluence } from '../policy/content-influence';
import type { PolicyEvaluation } from '../policy/policy-types';
import { MemoryStore } from '../storage/memory-store';

const influenceRuntimeFiles = [
  'src/contracts/content-influence.ts',
  'src/policy/content-influence.ts',
  'src/security/execution-grants.ts',
  'src/security/influence-scope.ts',
  'src/security/result-visibility.ts',
  'src/services/action-gate.ts',
  'src/storage/memory-store.ts',
];

const forbiddenNetworkModules = new Set([
  'axios',
  'got',
  'node-fetch',
  'node:dns',
  'node:http',
  'node:http2',
  'node:https',
  'node:net',
  'node:tls',
  'openai',
  'undici',
]);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('content-influence compute boundary', () => {
  it('keeps policy, exposure, and lifecycle modules free of network/model client dependencies', () => {
    for (const relativePath of influenceRuntimeFiles) {
      const source = fs.readFileSync(path.resolve(relativePath), 'utf8');
      const importedModules = [...source.matchAll(
        /(?:\bfrom\s*|\bimport\s*\()\s*['"]([^'"]+)['"]/gu,
      )].map((match) => match[1]!);

      expect(
        importedModules.filter((moduleName) => forbiddenNetworkModules.has(moduleName)),
        `${relativePath} must not import a network, model, embedding, or reputation client`,
      ).toEqual([]);
      expect(source, `${relativePath} must not issue a global fetch`).not.toMatch(/\bfetch\s*\(/u);
      expect(source, `${relativePath} must remain ESM-only and avoid hidden require calls`).not.toMatch(/\brequire\s*\(/u);
    }
  });

  it('performs pure evaluation plus bounded memory exposure work without a fetch or HTTP request', async () => {
    const fetchSpy = vi.fn(async () => {
      throw new Error('content-influence processing attempted a network fetch');
    });
    vi.stubGlobal('fetch', fetchSpy);
    const observedNetworkEvents: string[] = [];
    const channelNames = [
      'http.client.request.start',
      'undici:request:create',
    ];
    const subscriptions = channelNames.map((name) => {
      const channel = diagnosticsChannel.channel(name);
      const listener = () => observedNetworkEvents.push(name);
      channel.subscribe(listener);
      return { channel, listener };
    });

    try {
      const evaluation: PolicyEvaluation = {
        approval: 'never',
        decision: 'allow',
        matchedRule: 'guarded.write',
        reason: 'Test guarded write.',
        risk: 'low_risk_write',
        rule: {
          approval: 'never',
          influence: { allowFrom: ['none', 'organization_managed'], otherwise: 'required' },
        },
      };
      expect(evaluateContentInfluence(evaluation, {
        observedIntegrities: ['public_untrusted'],
        scopeVerified: true,
      })).toMatchObject({ effectiveDecision: 'require_approval' });

      const store = new MemoryStore();
      const influenceScopeId = `influence_${'a'.repeat(64)}`;
      await expect(store.recordContentExposure({
        influenceScopeId,
        integrity: 'public_untrusted',
        observedAt: '2026-07-15T00:00:00.000Z',
        policyVersionHash: 'network-boundary-policy',
        sourceId: 'public-web',
        sourceToolCallId: 'toolcall_network_boundary_source',
        workspaceId: 'network-boundary-workspace',
      })).resolves.toBe('created');
      await expect(store.listContentExposures({
        influenceScopeId,
        limit: MAX_INFLUENCE_EXPOSURES,
        workspaceId: 'network-boundary-workspace',
      })).resolves.toMatchObject({ overflow: false, revision: 1 });
    } finally {
      for (const { channel, listener } of subscriptions) channel.unsubscribe(listener);
    }

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(observedNetworkEvents).toEqual([]);
  });
});
