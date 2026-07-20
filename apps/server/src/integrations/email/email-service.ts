import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import type { Socket } from 'node:net';
import type { ApprovalNotificationChannel } from '../approval-notifications';
import type { ApprovalRecord, JsonObject, ToolCallRecord } from '../../models';
import type { ApprovalNotificationRecipient } from '../../services/approver-directory';
import { redactJsonObject } from '../../security/redaction';

export interface EmailSmtpConfig {
  host: string;
  password?: string;
  port: number;
  secure?: boolean;
  username?: string;
}

export interface EmailServiceConfig {
  approvalRecipient?: string;
  from: string;
  outboxDir: string;
  publicBaseUrl: string;
  smtp?: EmailSmtpConfig;
  transport: 'outbox' | 'smtp';
}

export type EmailServiceConfigProvider = () => EmailServiceConfig | Promise<EmailServiceConfig | undefined> | undefined;

interface EmailMessage {
  from: string;
  subject: string;
  text: string;
  to: string;
}

export class EmailService implements ApprovalNotificationChannel {
  readonly channelId = 'email.default';
  readonly description = 'Direct email approval notifications with a link back to ActionProxy.';
  readonly displayName = 'Email approvals';
  readonly isDefault = true;
  readonly provider = 'email' as const;

  private readonly getConfig: EmailServiceConfigProvider;

  constructor(config: EmailServiceConfig | EmailServiceConfigProvider) {
    this.getConfig = typeof config === 'function' ? config : () => config;
  }

  async isEnabled(): Promise<boolean> {
    return Boolean(await this.getConfig());
  }

  async notifyApprovalRequired(context: {
    approval: ApprovalRecord;
    recipients?: ApprovalNotificationRecipient[];
    toolCall: ToolCallRecord;
  }) {
    const config = await this.getConfig();
    if (!config) throw new Error('Email approval delivery is not fully configured.');

    const approvalUrl = approvalUrlFor(config, context.approval.id);
    const recipients = context.recipients ?? fallbackRecipients(config);
    if (recipients.length === 0) {
      return [{ error: 'No enabled approval recipients resolved.', status: 'failed' as const }];
    }

    return Promise.all(
      recipients.map(async (recipient) => {
        if (!recipient.email) {
          return {
            error: `Approver ${recipient.displayName} has no email address.`,
            recipientUserId: recipient.userId,
            status: 'failed' as const,
          };
        }

        try {
          const message = buildApprovalEmailMessage(config, context.approval, context.toolCall, approvalUrl, recipient.email);
          const sent = await this.send(config, message, `${context.approval.id}-${recipient.userId}`);
          return {
            data: {
              approvalUrl,
              recipientUserId: recipient.userId,
              transport: config.transport,
              ...sent.data,
            },
            destination: recipient.email,
            messageId: sent.messageId,
            recipientEmail: recipient.email,
            recipientUserId: recipient.userId,
            status: 'sent' as const,
          };
        } catch (error) {
          return {
            error: error instanceof Error ? error.message : String(error),
            recipientEmail: recipient.email,
            recipientUserId: recipient.userId,
            status: 'failed' as const,
          };
        }
      }),
    );
  }

  async sendTestMessage() {
    const config = await this.getConfig();
    if (!config) throw new Error('Email approval delivery is not fully configured.');
    if (!config.approvalRecipient) throw new Error('Email approval recipient is not configured.');

    const message = {
      from: config.from,
      subject: 'ActionProxy email integration test',
      text: 'ActionProxy email approval delivery is configured.',
      to: config.approvalRecipient,
    };
    const sent = await this.send(config, message, 'test');
    return {
      channelId: this.channelId,
      data: { transport: config.transport, ...sent.data },
      destination: config.approvalRecipient,
      messageId: sent.messageId,
      provider: this.provider,
      status: 'sent' as const,
    };
  }

  private async send(config: EmailServiceConfig, message: EmailMessage, approvalId: string) {
    if (config.transport === 'smtp') {
      if (!config.smtp) throw new Error('SMTP transport requires SMTP host and port.');
      const messageId = await sendSmtpMail(config.smtp, message);
      return { data: { smtpHost: config.smtp.host }, messageId };
    }

    fs.mkdirSync(config.outboxDir, { recursive: true });
    const messageId = `${approvalId}-${Date.now()}.json`;
    const outboxPath = path.join(config.outboxDir, messageId);
    fs.writeFileSync(outboxPath, `${JSON.stringify({ ...message, createdAt: new Date().toISOString() }, null, 2)}\n`, 'utf8');
    return { data: { outboxPath }, messageId };
  }
}

function buildApprovalEmailMessage(
  config: EmailServiceConfig,
  approval: ApprovalRecord,
  toolCall: ToolCallRecord,
  approvalUrl: string,
  to: string,
): EmailMessage {
  const payload = JSON.stringify(redactForNotification(toolCall.input), null, 2);
  return {
    from: config.from,
    subject: `ActionProxy approval required: ${toolCall.toolName}`,
    text: [
      `Approval required for ${toolCall.toolName}.`,
      '',
      `Risk: ${toolCall.risk ?? 'unknown'}`,
      `Requested by: ${toolCall.requestedBy}`,
      `Agent: ${toolCall.agentId}`,
      `Reason: ${toolCall.reason}`,
      '',
      `Approval ID: ${approval.id}`,
      `Tool call ID: ${toolCall.id}`,
      '',
      `Review and decide in ActionProxy: ${approvalUrl}`,
      '',
      'Payload summary:',
      payload,
    ].join('\n'),
    to,
  };
}

function fallbackRecipients(config: EmailServiceConfig): ApprovalNotificationRecipient[] {
  return config.approvalRecipient
    ? [
        {
          displayName: config.approvalRecipient,
          email: config.approvalRecipient,
          groups: [],
          principalId: 'configured-email-recipient',
          userId: 'configured-email-recipient',
        },
      ]
    : [];
}

function approvalUrlFor(config: EmailServiceConfig, approvalId: string): string {
  const baseUrl = config.publicBaseUrl.replace(/\/+$/, '');
  return `${baseUrl}/#/approvals/${encodeURIComponent(approvalId)}`;
}

function redactForNotification(input: JsonObject): JsonObject {
  return redactJsonObject(input, { replacement: '[redacted]' });
}

async function sendSmtpMail(config: EmailSmtpConfig, message: EmailMessage): Promise<string> {
  const socket = await connectSmtp(config);
  const reader = new SmtpReader(socket);
  const messageId = `<actionproxy-${Date.now()}@localhost>`;

  try {
    await reader.expect(220);
    await smtpCommand(socket, reader, `EHLO actionproxy.local`, 250);
    if (config.username && config.password) {
      const credentials = Buffer.from(`\0${config.username}\0${config.password}`, 'utf8').toString('base64');
      await smtpCommand(socket, reader, `AUTH PLAIN ${credentials}`, 235);
    }
    await smtpCommand(socket, reader, `MAIL FROM:<${message.from}>`, 250);
    await smtpCommand(socket, reader, `RCPT TO:<${message.to}>`, 250);
    await smtpCommand(socket, reader, 'DATA', 354);
    socket.write(formatSmtpMessage(message, messageId));
    await reader.expect(250);
    await smtpCommand(socket, reader, 'QUIT', 221);
    return messageId;
  } finally {
    socket.end();
  }
}

function connectSmtp(config: EmailSmtpConfig): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = config.secure
      ? tls.connect({ host: config.host, port: config.port }, () => resolve(socket))
      : net.connect({ host: config.host, port: config.port }, () => resolve(socket));
    socket.once('error', reject);
  });
}

async function smtpCommand(socket: Socket, reader: SmtpReader, command: string, expectedCode: number): Promise<void> {
  socket.write(`${command}\r\n`);
  await reader.expect(expectedCode);
}

function formatSmtpMessage(message: EmailMessage, messageId: string): string {
  const body = message.text.replaceAll('\n.', '\n..');
  return [
    `From: ${message.from}`,
    `To: ${message.to}`,
    `Subject: ${message.subject}`,
    `Message-ID: ${messageId}`,
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
    '.',
    '',
  ].join('\r\n');
}

class SmtpReader {
  private buffer = '';
  private readonly waiting: Array<() => void> = [];

  constructor(socket: Socket) {
    socket.on('data', (chunk) => {
      this.buffer += Buffer.from(chunk).toString('utf8');
      for (const notify of this.waiting.splice(0)) notify();
    });
  }

  async expect(expectedCode: number): Promise<void> {
    const response = await this.readResponse();
    if (response.code !== expectedCode) {
      throw new Error(`SMTP expected ${expectedCode}, received ${response.code}: ${response.message}`);
    }
  }

  private async readResponse(): Promise<{ code: number; message: string }> {
    while (true) {
      const parsed = this.tryReadResponse();
      if (parsed) return parsed;
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    }
  }

  private tryReadResponse(): { code: number; message: string } | undefined {
    const lines = this.buffer.split(/\r?\n/);
    for (let index = 0; index < lines.length - 1; index += 1) {
      const line = lines[index] ?? '';
      if (/^\d{3} /.test(line)) {
        const responseLines = lines.slice(0, index + 1);
        this.buffer = lines.slice(index + 1).join('\n');
        return {
          code: Number(line.slice(0, 3)),
          message: responseLines.join('\n'),
        };
      }
    }
    return undefined;
  }
}
