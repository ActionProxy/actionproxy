import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTelemetryRecorder, safeTelemetryAttributes } from './telemetry';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('telemetry', () => {
  it('drops unsupported and secret-like attributes', () => {
    expect(
      safeTelemetryAttributes({
        apiToken: 'raw-secret-token',
        input: 'raw payload',
        'input.hash': 'hash_123',
        'tool.name': 'gmail.send_email',
      }),
    ).toEqual({
      'input.hash': 'hash_123',
      'tool.name': 'gmail.send_email',
    });
  });

  it('does nothing when telemetry is disabled', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const recorder = createTelemetryRecorder({
      enabled: false,
      otlpEndpoint: 'http://collector:4318',
      otlpHeaders: {},
      serviceName: 'actionproxy-test',
    });

    await recorder.recordLifecycle('tool_call.submit', {
      'tool.name': 'docs.search',
      'tool_call.id': 'toolcall_1',
    });

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('exports lifecycle traces and metrics without raw payload attributes', async () => {
    const fetchMock = vi.fn(async (_input: string | URL, _init?: RequestInit) => new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);

    const recorder = createTelemetryRecorder({
      enabled: true,
      otlpEndpoint: 'http://collector:4318',
      otlpHeaders: { 'x-collector-token': 'collector-secret' },
      serviceName: 'actionproxy-test',
    });

    await recorder.recordLifecycle('policy.evaluate', {
      input: 'customer@example.com raw prompt',
      password: 'raw-password',
      'policy.decision': 'require_approval',
      'tool.name': 'gmail.send_email',
      'workspace.id': 'default',
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const calls = fetchMock.mock.calls as Array<[string | URL, RequestInit]>;
    expect(calls.map((call) => String(call[0])).sort()).toEqual([
      'http://collector:4318/v1/metrics',
      'http://collector:4318/v1/traces',
    ]);
    const exportedBodies = calls.map((call) => String(call[1].body)).join('\n');
    expect(exportedBodies).toContain('policy.evaluate');
    expect(exportedBodies).toContain('gmail.send_email');
    expect(exportedBodies).not.toContain('customer@example.com');
    expect(exportedBodies).not.toContain('raw-password');
  });
});
