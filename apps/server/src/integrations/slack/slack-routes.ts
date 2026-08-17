import type { FastifyInstance } from 'fastify';
import { ConflictError, NotFoundError } from '../../errors';
import type { AuthService } from '../../security/auth-service';
import type { ApproverDirectoryService } from '../../services/approver-directory';
import type { ActionProxyService } from '../../services/action-gate';
import { SLACK_APPROVE_ACTION_ID, SLACK_REJECT_ACTION_ID } from './slack-blocks';
import { verifySlackSignature } from './verify-slack-signature';

export interface SlackInteractionRouteOptions {
  approverDirectory?: ApproverDirectoryService;
  authService: AuthService;
  signingSecret?: string;
  signingSecretProvider?: () => Promise<string | undefined> | string | undefined;
}

interface SlackInteractionPayload {
  actions?: Array<{
    action_id?: string;
    value?: string;
  }>;
  channel?: {
    id?: string;
  };
  message?: {
    ts?: string;
  };
  type?: string;
  user?: {
    id?: string;
    name?: string;
    username?: string;
  };
}

export async function registerSlackInteractionRoutes(
  app: FastifyInstance,
  actionProxy: ActionProxyService,
  options: SlackInteractionRouteOptions,
): Promise<void> {
  if (!app.hasContentTypeParser('application/x-www-form-urlencoded')) {
    app.addContentTypeParser('application/x-www-form-urlencoded', { parseAs: 'string' }, (_request, body, done) => {
      done(null, body);
    });
  }

  app.post('/v1/slack/interactions', async (request, reply) => {
    const signingSecret = options.signingSecretProvider ? await options.signingSecretProvider() : options.signingSecret;
    if (!signingSecret) {
      return reply.status(503).send({ error: 'slack_not_configured' });
    }

    const rawBody = typeof request.body === 'string' ? request.body : '';
    const signature = headerValue(request.headers['x-slack-signature']);
    const timestamp = headerValue(request.headers['x-slack-request-timestamp']);
    const isVerified = verifySlackSignature({
      body: rawBody,
      signature,
      signingSecret,
      timestamp,
    });

    if (!isVerified) {
      return reply.status(401).send({ error: 'invalid_slack_signature' });
    }

    const payload = parsePayload(rawBody);
    const action = payload.actions?.[0];
    const actionId = action?.action_id;
    const approvalId = action?.value;
    const slackUserId = slackUser(payload);
    const directoryUser = await options.approverDirectory?.findEnabledUserBySlackUserId(
      options.authService.workspaceId(),
      slackUserId,
    );
    const auth = directoryUser
      ? options.approverDirectory!.slackAuthContext(directoryUser)
      : await options.authService.slackContext(options.authService.slackUserMapping(slackUserId), slackUserId);
    const actor = auth.email ?? auth.principalId;

    if (payload.type !== 'block_actions' || !actionId || !approvalId) {
      return reply.send({ response_type: 'ephemeral', text: 'ActionProxy could not process this Slack action.' });
    }

    if (actionId !== SLACK_APPROVE_ACTION_ID && actionId !== SLACK_REJECT_ACTION_ID) {
      return reply.send({ response_type: 'ephemeral', text: 'ActionProxy ignored an unsupported Slack action.' });
    }

    try {
      if (actionId === SLACK_APPROVE_ACTION_ID) {
        await actionProxy.recordAuditEvent('slack.interaction.approved', {
          approvalId,
          actor,
          auth,
          data: interactionAuditData(payload, actionId),
          workspaceId: auth.workspaceId,
        });
        const result = await actionProxy.approveApproval(approvalId, {
          approvedBy: actor,
          note: 'Approved from Slack',
        }, auth, { source: 'slack' });
        return reply.send({
          response_type: 'ephemeral',
          text: `Approved ${result.toolCall.toolName}.`,
        });
      }

      await actionProxy.recordAuditEvent('slack.interaction.rejected', {
        approvalId,
        actor,
        auth,
        data: interactionAuditData(payload, actionId),
        workspaceId: auth.workspaceId,
      });
      const result = await actionProxy.rejectApproval(approvalId, {
        rejectedBy: actor,
        reason: 'Rejected from Slack',
      }, auth, { source: 'slack' });
      return reply.send({
        response_type: 'ephemeral',
        text: `Rejected ${result.toolCall.toolName}.`,
      });
    } catch (error) {
      await actionProxy.recordAuditEvent('slack.interaction.failed', {
        approvalId,
        actor,
        auth,
        data: {
          ...interactionAuditData(payload, actionId),
          error: error instanceof Error ? error.message : String(error),
        },
        workspaceId: auth.workspaceId,
      });

      if (error instanceof NotFoundError || error instanceof ConflictError) {
        return reply.send({
          response_type: 'ephemeral',
          text: error.message,
        });
      }

      throw error;
    }
  });
}

function parsePayload(rawBody: string): SlackInteractionPayload {
  const payload = new URLSearchParams(rawBody).get('payload');
  if (!payload) return {};

  try {
    return JSON.parse(payload) as SlackInteractionPayload;
  } catch {
    return {};
  }
}

function slackUser(payload: SlackInteractionPayload): string {
  const user = payload.user?.id ?? payload.user?.username ?? payload.user?.name ?? 'unknown';
  return user;
}

function interactionAuditData(payload: SlackInteractionPayload, actionId: string): Record<string, unknown> {
  return {
    actionId,
    channelId: payload.channel?.id ?? null,
    messageTs: payload.message?.ts ?? null,
    slackUser: payload.user ?? null,
  };
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
