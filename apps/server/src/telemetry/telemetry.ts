import { randomBytes } from 'node:crypto';
import type { TelemetryConfig } from '../config';

export type TelemetryAttributeValue = boolean | number | string | undefined;
export type TelemetryAttributes = Record<string, TelemetryAttributeValue>;

export interface TelemetryRecorder {
  recordLifecycle(name: string, attributes?: TelemetryAttributes): Promise<void>;
}

const allowedAttributeKeys = new Set([
  'actionproxy.event',
  'approval.id',
  'approval.status',
  'audit.checked',
  'audit.error_count',
  'audit.valid',
  'decision',
  'error.present',
  'execution.status',
  'grant.id',
  'grant.status',
  'input.hash',
  'matched_rule',
  'policy.decision',
  'policy.version.hash',
  'policy.version.id',
  'receipt.hash',
  'receipt.id',
  'status',
  'tool.name',
  'tool_call.id',
  'workspace.id',
]);

export const noopTelemetry: TelemetryRecorder = {
  async recordLifecycle() {
    // Disabled telemetry must never affect request handling.
  },
};

export function createTelemetryRecorder(config: TelemetryConfig): TelemetryRecorder {
  if (!config.enabled || !config.otlpEndpoint) return noopTelemetry;
  return new OtlpHttpTelemetryRecorder(config);
}

class OtlpHttpTelemetryRecorder implements TelemetryRecorder {
  private readonly metricsUrl: string;
  private readonly tracesUrl: string;

  constructor(private readonly config: TelemetryConfig) {
    const endpoint = config.otlpEndpoint ?? '';
    this.tracesUrl = otlpUrl(endpoint, 'traces');
    this.metricsUrl = otlpUrl(endpoint, 'metrics');
  }

  async recordLifecycle(name: string, attributes: TelemetryAttributes = {}): Promise<void> {
    const safeAttributes = {
      ...safeTelemetryAttributes(attributes),
      'actionproxy.event': safeName(name),
    };
    const now = unixNano();
    await Promise.all([
      this.post(this.tracesUrl, tracePayload(this.config.serviceName, name, safeAttributes, now)),
      this.post(this.metricsUrl, metricPayload(this.config.serviceName, name, safeAttributes, now)),
    ]);
  }

  private async post(url: string, body: unknown): Promise<void> {
    const response = await fetch(url, {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/json',
        ...this.config.otlpHeaders,
      },
      method: 'POST',
    });
    if (!response.ok) {
      throw new Error(`OTLP export failed with HTTP ${response.status}.`);
    }
  }
}

export function safeTelemetryAttributes(attributes: TelemetryAttributes): Record<string, boolean | number | string> {
  const output: Record<string, boolean | number | string> = {};
  for (const [key, value] of Object.entries(attributes)) {
    if (!allowedAttributeKeys.has(key) || value === undefined || secretLikeKey(key)) continue;
    if (typeof value === 'string') {
      output[key] = value.length > 256 ? `${value.slice(0, 253)}...` : value;
    } else {
      output[key] = value;
    }
  }
  return output;
}

function tracePayload(
  serviceName: string,
  name: string,
  attributes: Record<string, boolean | number | string>,
  timeUnixNano: string,
): Record<string, unknown> {
  return {
    resourceSpans: [
      {
        resource: resource(serviceName),
        scopeSpans: [
          {
            scope: { name: 'actionproxy.lifecycle' },
            spans: [
              {
                attributes: otlpAttributes(attributes),
                endTimeUnixNano: timeUnixNano,
                kind: 1,
                name: `actionproxy.${safeName(name)}`,
                spanId: randomHex(8),
                startTimeUnixNano: timeUnixNano,
                traceId: randomHex(16),
              },
            ],
          },
        ],
      },
    ],
  };
}

function metricPayload(
  serviceName: string,
  name: string,
  attributes: Record<string, boolean | number | string>,
  timeUnixNano: string,
): Record<string, unknown> {
  return {
    resourceMetrics: [
      {
        resource: resource(serviceName),
        scopeMetrics: [
          {
            metrics: [
              {
                name: `actionproxy.${safeName(name)}.count`,
                sum: {
                  aggregationTemporality: 2,
                  dataPoints: [
                    {
                      asInt: '1',
                      attributes: otlpAttributes(attributes),
                      timeUnixNano,
                    },
                  ],
                  isMonotonic: true,
                },
                unit: '1',
              },
            ],
            scope: { name: 'actionproxy.lifecycle' },
          },
        ],
      },
    ],
  };
}

function resource(serviceName: string): Record<string, unknown> {
  return {
    attributes: otlpAttributes({ 'service.name': serviceName }),
  };
}

function otlpAttributes(attributes: Record<string, boolean | number | string>): Array<Record<string, unknown>> {
  return Object.entries(attributes).map(([key, value]) => ({
    key,
    value:
      typeof value === 'boolean'
        ? { boolValue: value }
        : typeof value === 'number'
          ? { doubleValue: value }
          : { stringValue: value },
  }));
}

function otlpUrl(endpoint: string, signal: 'metrics' | 'traces'): string {
  const trimmed = endpoint.replace(/\/+$/, '');
  if (trimmed.endsWith(`/v1/${signal}`)) return trimmed;
  if (trimmed.endsWith('/v1/traces') || trimmed.endsWith('/v1/metrics')) {
    return trimmed.replace(/\/v1\/(traces|metrics)$/, `/v1/${signal}`);
  }
  return `${trimmed}/v1/${signal}`;
}

function safeName(name: string): string {
  return name.trim().toLowerCase().replace(/[^a-z0-9_.-]+/g, '_').replace(/^_+|_+$/g, '') || 'event';
}

function unixNano(): string {
  return String(BigInt(Date.now()) * 1_000_000n);
}

function randomHex(bytes: number): string {
  return randomBytes(bytes).toString('hex');
}

function secretLikeKey(key: string): boolean {
  return /secret|token|password|authorization|credential|cookie/i.test(key);
}
