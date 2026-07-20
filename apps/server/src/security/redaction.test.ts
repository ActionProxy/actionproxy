import { describe, expect, it } from 'vitest';
import { redactJsonObject, redactJsonObjectAtPath } from './redaction';

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

  it('applies policy paths relative to the semantic object root', () => {
    expect(redactJsonObjectAtPath(
      { body: 'sensitive message', subject: 'Public subject' },
      'input',
      { fields: ['input.body'] },
    )).toEqual({ body: '[REDACTED]', subject: 'Public subject' });
  });
});
