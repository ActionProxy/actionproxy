export interface EmailPublicBaseUrlOptions {
  label?: string;
  requireHttps?: boolean;
}

export function normalizeEmailPublicBaseUrl(
  value: string | undefined,
  options: EmailPublicBaseUrlOptions = {},
): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;

  const label = options.label ?? 'Email approval review URL';
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`${label} must be an absolute HTTP or HTTPS URL.`);
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${label} must use HTTP or HTTPS.`);
  }
  if (options.requireHttps && parsed.protocol !== 'https:') {
    throw new Error(`${label} must use HTTPS.`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not contain embedded credentials.`);
  }
  if (trimmed.includes('?') || trimmed.includes('#')) {
    throw new Error(`${label} must not contain a query string or fragment.`);
  }

  const pathname = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/+$/, '');
  return `${parsed.protocol}//${parsed.host}${pathname}`;
}

export function localEmailPublicBaseUrl(port: number): string {
  return `http://127.0.0.1:${port}`;
}
