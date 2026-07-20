import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import {
  CONSERVATIVE_EXECUTOR_CAPABILITIES_V1,
  createExecutionAuthorizationAuthority,
  type ActionExecutor,
  type AuthorizedExecutionInvocationV1,
  type ExecutionAuthorization,
  type ExecutionAuthorizationBindingV1,
  type ExecutorCapabilitiesV1,
} from '../contracts/execution-authorization';
import { hashJson } from '../security/crypto';
import { ToolRegistry } from './tool-registry';

const fixture = JSON.parse(
  fs.readFileSync(path.resolve(process.cwd(), '../../fixtures/contracts/execution-authorization-v1.json'), 'utf8'),
) as { binding: ExecutionAuthorizationBindingV1 };

describe('ToolRegistry execution authorization boundary', () => {
  it('implements the mandatory ActionExecutor contract and declares conservative capabilities', async () => {
    const authority = createExecutionAuthorizationAuthority();
    const registry = new ToolRegistry(authority);
    const execute = vi.fn(async (input) => ({ input, ok: true }));
    const input = { query: 'refund' };
    const binding = localBinding(input);
    const authorization = authority.issue({ binding, capabilities: registry.describe().capabilities });
    registry.register(binding.action.toolName, execute);

    expectTypeOf(registry).toMatchTypeOf<ActionExecutor>();
    expectTypeOf<Parameters<ToolRegistry['execute']>>().toEqualTypeOf<[AuthorizedExecutionInvocationV1]>();
    expect(registry.describe()).toEqual({
      capabilities: CONSERVATIVE_EXECUTOR_CAPABILITIES_V1,
      executorId: 'actionproxy.local-tool-registry',
    });
    await expect(
      registry.execute({ authorization, authorizationBinding: binding, input, toolName: binding.action.toolName }),
    ).resolves.toEqual({ input, ok: true });
    expect(execute).toHaveBeenCalledOnce();
  });

  it('rejects missing, fabricated, serialized, and foreign-authority capabilities before executor lookup', () => {
    const authority = createExecutionAuthorizationAuthority();
    const foreignAuthority = createExecutionAuthorizationAuthority();
    const registry = new ToolRegistry(authority);
    const execute = vi.fn(async () => ({ ok: true }));
    const input = { query: 'refund' };
    const binding = localBinding(input);
    const foreign = foreignAuthority.issue({ binding });
    const tokens = [
      undefined as unknown as ExecutionAuthorization,
      Object.freeze({}) as ExecutionAuthorization,
      JSON.parse(JSON.stringify(foreign)) as ExecutionAuthorization,
      foreign,
    ];
    registry.register(binding.action.toolName, execute);

    for (const authorization of tokens) {
      expect(() =>
        registry.execute({ authorization, authorizationBinding: binding, input, toolName: binding.action.toolName }),
      ).toThrowError(expect.objectContaining({ code: 'execution_authorization_invalid' }));
    }
    expect(execute).not.toHaveBeenCalled();
  });

  it('rejects expired and replayed capabilities without a duplicate side effect', async () => {
    let now = new Date('2026-07-12T00:00:00.000Z');
    const authority = createExecutionAuthorizationAuthority({ clock: () => now });
    const registry = new ToolRegistry(authority);
    const execute = vi.fn(async () => ({ ok: true }));
    const input = { query: 'refund' };
    const binding = localBinding(input);
    registry.register(binding.action.toolName, execute);

    const expired = authority.issue({ binding, ttlMs: 1 });
    now = new Date('2026-07-12T00:00:00.001Z');
    expect(() =>
      registry.execute({ authorization: expired, authorizationBinding: binding, input, toolName: binding.action.toolName }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_expired' }));

    const once = authority.issue({ binding });
    await expect(
      registry.execute({ authorization: once, authorizationBinding: binding, input, toolName: binding.action.toolName }),
    ).resolves.toEqual({ ok: true });
    expect(() =>
      registry.execute({ authorization: once, authorizationBinding: binding, input, toolName: binding.action.toolName }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_replayed' }));
    expect(execute).toHaveBeenCalledOnce();
  });

  it.each([
    ['tenant', (binding: ExecutionAuthorizationBindingV1) => { binding.tenant.workspaceId = 'tenant-mutated'; }],
    ['policy', (binding: ExecutionAuthorizationBindingV1) => { binding.policy.versionHash = 'policy-mutated'; }],
    ['attempt', (binding: ExecutionAuthorizationBindingV1) => { binding.execution.attemptId = 'attempt-mutated'; }],
  ] as const)('rejects current %s mutation before invoking the executor', (_label, mutate) => {
    const authority = createExecutionAuthorizationAuthority();
    const registry = new ToolRegistry(authority);
    const execute = vi.fn(async () => ({ ok: true }));
    const input = { query: 'refund' };
    const binding = localBinding(input);
    const expected = mutableBinding(binding);
    mutate(expected);
    const authorization = authority.issue({ binding });
    registry.register(binding.action.toolName, execute);

    expect(() =>
      registry.execute({ authorization, authorizationBinding: expected, input, toolName: binding.action.toolName }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_binding_mismatch' }));
    expect(execute).not.toHaveBeenCalled();
  });

  it('derives exact input, tool, and executor identity instead of trusting invocation claims', () => {
    const authority = createExecutionAuthorizationAuthority();
    const registry = new ToolRegistry(authority);
    const original = { query: 'refund' };
    const binding = localBinding(original);
    const executeOriginal = vi.fn(async () => ({ ok: true }));
    const executeOther = vi.fn(async () => ({ ok: true }));
    registry.register(binding.action.toolName, executeOriginal);
    registry.register('docs.other', executeOther);

    const wrongInput = authority.issue({ binding });
    expect(() =>
      registry.execute({
        authorization: wrongInput,
        authorizationBinding: binding,
        input: { query: 'mutated' },
        toolName: binding.action.toolName,
      }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_binding_mismatch' }));

    const wrongTool = authority.issue({ binding });
    expect(() =>
      registry.execute({
        authorization: wrongTool,
        authorizationBinding: binding,
        input: original,
        toolName: 'docs.other',
      }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_binding_mismatch' }));

    const externalBinding = mutableBinding(binding);
    externalBinding.executor.id = 'actionproxy.external-runner';
    externalBinding.execution.mode = 'external_grant';
    externalBinding.execution.grantId = 'grant-forged';
    const wrongExecutor = authority.issue({ binding: externalBinding });
    expect(() =>
      registry.execute({
        authorization: wrongExecutor,
        authorizationBinding: externalBinding,
        input: original,
        toolName: binding.action.toolName,
      }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_binding_mismatch' }));

    expect(executeOriginal).not.toHaveBeenCalled();
    expect(executeOther).not.toHaveBeenCalled();
  });

  it('rejects elevated capability claims and keeps executor credentials behind the invoked closure', async () => {
    const authority = createExecutionAuthorizationAuthority();
    const registry = new ToolRegistry(authority);
    const input = { query: 'refund' };
    const binding = localBinding(input);
    const credentials = { accessToken: 'credential-canary-t5' };
    const execute = vi.fn(async () => ({ ok: credentials.accessToken.length > 0 }));
    const elevated = mutableCapabilities();
    (elevated.providerIdempotency as { supported: boolean }).supported = true;
    const authorization = authority.issue({ binding, capabilities: elevated });
    registry.register(binding.action.toolName, execute);

    expect(() =>
      registry.execute({ authorization, authorizationBinding: binding, input, toolName: binding.action.toolName }),
    ).toThrowError(expect.objectContaining({ code: 'execution_authorization_binding_mismatch' }));
    expect(JSON.stringify(authority.inspect(authorization))).not.toContain(credentials.accessToken);
    expect(execute).not.toHaveBeenCalled();

    const valid = authority.issue({ binding, capabilities: registry.describe().capabilities });
    const result = await registry.execute({
      authorization: valid,
      authorizationBinding: binding,
      input,
      toolName: binding.action.toolName,
    });
    expect(result).toEqual({ ok: true });
    expect(execute).toHaveBeenCalledWith(input);
    expect(JSON.stringify({ projection: authority.inspect(valid), result })).not.toContain(credentials.accessToken);
  });

  it('confines production registry dispatch and authorization issuance to the core boundaries', () => {
    const sourceRoot = path.resolve(process.cwd(), 'src');
    const files = productionTypeScriptFiles(sourceRoot);
    const registryDispatchCallers = files
      .filter((file) => /\btools\.execute\s*\(/u.test(fs.readFileSync(file, 'utf8')))
      .map((file) => path.relative(sourceRoot, file));
    const authorizationIssuers = files
      .filter((file) => /\bexecutionAuthorizations\.issue\s*\(/u.test(fs.readFileSync(file, 'utf8')))
      .map((file) => path.relative(sourceRoot, file))
      .sort();

    expect(registryDispatchCallers).toEqual(['services/action-gate.ts']);
    expect(authorizationIssuers).toEqual(['security/execution-grants.ts', 'services/action-gate.ts']);
  });
});

function localBinding(input: Record<string, unknown>): ExecutionAuthorizationBindingV1 {
  const binding = mutableBinding(fixture.binding);
  binding.action.inputHash = hashJson(input);
  binding.action.toolName = 'docs.search';
  binding.approval = {
    approvalId: null,
    authorizationHash: null,
    authorizationNonce: null,
    receiptHash: 'receipt-hash',
    receiptId: 'receipt-id',
  };
  binding.decision.outcome = 'allow';
  binding.execution.grantId = null;
  binding.execution.mode = 'local_mock';
  binding.executor.id = 'actionproxy.local-tool-registry';
  return binding;
}

function mutableBinding(binding: ExecutionAuthorizationBindingV1): ExecutionAuthorizationBindingV1 {
  return JSON.parse(JSON.stringify(binding)) as ExecutionAuthorizationBindingV1;
}

function mutableCapabilities(): ExecutorCapabilitiesV1 {
  return JSON.parse(JSON.stringify(CONSERVATIVE_EXECUTOR_CAPABILITIES_V1)) as ExecutorCapabilitiesV1;
}

function productionTypeScriptFiles(directory: string): string[] {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) return productionTypeScriptFiles(file);
    if (!entry.isFile() || !entry.name.endsWith('.ts') || entry.name.endsWith('.test.ts')) return [];
    return [file];
  });
}
