import { describe, expect, it } from 'vitest';
import {
  localEmailPublicBaseUrl,
  normalizeEmailPublicBaseUrl,
} from './public-base-url';

describe('email approval review URL', () => {
  it('normalizes an absolute HTTP or HTTPS URL while preserving a path prefix', () => {
    expect(normalizeEmailPublicBaseUrl('  https://console.example.com/actionproxy///  ')).toBe(
      'https://console.example.com/actionproxy',
    );
    expect(normalizeEmailPublicBaseUrl('http://127.0.0.1:8787/')).toBe(
      'http://127.0.0.1:8787',
    );
  });

  it.each([
    ['relative path', '/actionproxy'],
    ['unsupported protocol', 'ftp://console.example.com'],
    ['credentials', urlWithCredentials()],
    ['query string', 'https://console.example.com?workspace=demo'],
    ['empty query string', 'https://console.example.com?'],
    ['fragment', 'https://console.example.com/#/approvals'],
  ])('rejects %s', (_label, value) => {
    expect(() => normalizeEmailPublicBaseUrl(value)).toThrow();
  });

  it('requires HTTPS when the caller requests a public-deployment URL', () => {
    expect(() =>
      normalizeEmailPublicBaseUrl('http://console.example.com', {
        requireHttps: true,
      }),
    ).toThrow('must use HTTPS');
  });

  it('builds the server-side local-development fallback from the configured port', () => {
    expect(localEmailPublicBaseUrl(8787)).toBe('http://127.0.0.1:8787');
  });
});

function urlWithCredentials(): string {
  const value = new URL('https://console.example.com');
  value.username = 'user';
  value.password = 'secret';
  return value.toString();
}
