import type { JsonObject } from '../models';
import {
  CONSERVATIVE_EXECUTOR_CAPABILITIES_V1,
  ExecutionAuthorizationError,
  type ActionExecutor,
  type AuthorizedExecutionInvocationV1,
  type ExecutionAuthorizationAuthority,
} from '../contracts/execution-authorization';
import { canonicalJsonStringify } from '../contracts/action-request';
import { hashJson } from '../security/crypto';

export type ToolExecutor = (input: JsonObject) => Promise<unknown>;

export class ToolRegistry implements ActionExecutor {
  private tools = new Map<string, ToolExecutor>();

  constructor(private readonly executionAuthorizations: ExecutionAuthorizationAuthority) {}

  register(name: string, executor: ToolExecutor): void {
    this.tools.set(name, executor);
  }

  has(name: string): boolean {
    return this.tools.has(name);
  }

  describe(): ReturnType<ActionExecutor['describe']> {
    return {
      capabilities: CONSERVATIVE_EXECUTOR_CAPABILITIES_V1,
      executorId: 'actionproxy.local-tool-registry',
    };
  }

  execute(invocation: AuthorizedExecutionInvocationV1): Promise<unknown> {
    const descriptor = this.describe();
    const expectedBinding = {
      ...invocation.authorizationBinding,
      action: {
        ...invocation.authorizationBinding.action,
        inputHash: hashJson(invocation.input),
        toolName: invocation.toolName,
      },
      executor: { id: descriptor.executorId },
    };
    const projection = this.executionAuthorizations.inspect(invocation.authorization);
    if (
      canonicalJsonStringify(projection.capabilities) !==
      canonicalJsonStringify(descriptor.capabilities)
    ) {
      throw new ExecutionAuthorizationError(
        'execution_authorization_binding_mismatch',
        'Execution authorization capabilities do not match the local executor.',
      );
    }
    this.executionAuthorizations.consume(invocation.authorization, expectedBinding);

    const executor = this.tools.get(invocation.toolName);
    if (!executor) {
      throw new Error(`No tool registered for ${invocation.toolName}`);
    }
    return executor(invocation.input);
  }

  list(): string[] {
    return [...this.tools.keys()].sort();
  }
}
