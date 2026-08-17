import { hashJson } from '../security/crypto';

export interface NativeExecutionAuthorizationBindingV1 {
  attemptId: string;
  grantId: string;
  intentHash: string;
  phase: 'dispatch' | 'outcome';
  toolCallId: string;
  version: 'actionproxy.native-execution-binding.v1';
  workspaceId: string;
}

export interface NativeExecutionAuthorizationProjectionV1 {
  bindingHash: string;
  version: 'actionproxy.native-execution-authorization.v1';
}

/** Opaque, in-process capability. It has no serializable authority. */
export interface NativeExecutionAuthorization extends NativeExecutionAuthorizationProjectionV1 {
  readonly capability: object;
}

export interface NativeExecutionAuthorizationIssuer {
  issue(binding: NativeExecutionAuthorizationBindingV1): NativeExecutionAuthorization;
}

export interface NativeExecutionAuthorizationVerifier {
  consume(
    authorization: NativeExecutionAuthorization,
    binding: NativeExecutionAuthorizationBindingV1,
  ): NativeExecutionAuthorizationProjectionV1;
}

export function createNativeExecutionAuthorizationAuthority(): {
  issuer: NativeExecutionAuthorizationIssuer;
  verifier: NativeExecutionAuthorizationVerifier;
} {
  const active = new WeakMap<object, string>();
  const consumed = new WeakSet<object>();
  return {
    issuer: {
      issue(binding) {
        const capability = Object.freeze({});
        const bindingHash = hashJson(binding);
        active.set(capability, bindingHash);
        return Object.freeze({
          bindingHash,
          capability,
          version: 'actionproxy.native-execution-authorization.v1' as const,
        });
      },
    },
    verifier: {
      consume(authorization, binding) {
        if (
          authorization.version !== 'actionproxy.native-execution-authorization.v1' ||
          typeof authorization.capability !== 'object' ||
          authorization.capability === null
        ) {
          throw new NativeExecutionAuthorizationError('invalid_capability');
        }
        if (consumed.has(authorization.capability)) {
          throw new NativeExecutionAuthorizationError('already_consumed');
        }
        const expected = hashJson(binding);
        if (
          authorization.bindingHash !== expected ||
          active.get(authorization.capability) !== expected
        ) {
          throw new NativeExecutionAuthorizationError('binding_mismatch');
        }
        active.delete(authorization.capability);
        consumed.add(authorization.capability);
        return {
          bindingHash: expected,
          version: authorization.version,
        };
      },
    },
  };
}

export class NativeExecutionAuthorizationError extends Error {
  constructor(readonly code: 'already_consumed' | 'binding_mismatch' | 'invalid_capability') {
    super(`Native execution authorization rejected: ${code}.`);
    this.name = 'NativeExecutionAuthorizationError';
  }
}
