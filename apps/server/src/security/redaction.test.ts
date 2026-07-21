import { describe, expect, it } from 'vitest';
import { redactJsonObject, redactJsonObjectAtPath, redactToolCallResult } from './redaction';

describe('redaction', () => {
  it('redacts common credential keys recursively across naming styles', () => {
    const redacted = redactJsonObject({
      apiToken: 'api-secret',
      nested: {
        access_token: 'access-secret',
        credentials: { password: 'password-secret' },
        refreshToken: 'refresh-secret',
      },
    });

    expect(redacted).toEqual({
      apiToken: '[REDACTED]',
      nested: {
        access_token: '[REDACTED]',
        credentials: '[REDACTED]',
        refreshToken: '[REDACTED]',
      },
    });
  });

  it('redacts only ActionProxy authorization fields from tool-call results', () => {
    expect(redactToolCallResult({
      externalExecutionOutcome: {
        nonce: 'provider-nonce',
        signature: 'provider-signature',
      },
      grant: {
        id: 'grant_1',
        nonce: 'grant-nonce',
        signature: 'grant-signature',
      },
      receipt: { id: 'receipt_1', signature: 'receipt-signature' },
    })).toEqual({
      externalExecutionOutcome: {
        nonce: 'provider-nonce',
        signature: 'provider-signature',
      },
      grant: {
        id: 'grant_1',
        nonce: '[REDACTED]',
        signature: '[REDACTED]',
      },
      receipt: { id: 'receipt_1', signature: '[REDACTED]' },
    });
  });

  it('applies policy paths relative to the semantic object root', () => {
    expect(redactJsonObjectAtPath(
      { body: 'sensitive message', subject: 'Public subject' },
      'input',
      { fields: ['input.body'] },
    )).toEqual({ body: '[REDACTED]', subject: 'Public subject' });
  });
});
