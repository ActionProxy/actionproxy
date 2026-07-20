import type { PolicyFile } from './policy-types';
import { parsePolicy, writePolicy } from './load-policy';

export class PolicyManager {
  constructor(
    private readonly policyPath: string,
    private readonly policy: PolicyFile,
  ) {}

  getPolicy(): PolicyFile {
    return this.policy;
  }

  replacePolicy(input: unknown): PolicyFile {
    const nextPolicy = writePolicy(this.policyPath, parsePolicy(input));
    this.policy.version = nextPolicy.version;
    this.policy.default = nextPolicy.default;
    this.policy.tools = nextPolicy.tools;
    return this.policy;
  }
}
