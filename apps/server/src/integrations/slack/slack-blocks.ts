import type { ApprovalRecord, ToolCallRecord } from '../../models';
import { redactJsonObject } from '../../security/redaction';

export const SLACK_APPROVE_ACTION_ID = 'actionproxy_approval_approve';
export const SLACK_REJECT_ACTION_ID = 'actionproxy_approval_reject';

type SlackText = {
  text: string;
  type: 'mrkdwn' | 'plain_text';
  emoji?: boolean;
};

export type SlackBlock = Record<string, unknown>;

export function buildApprovalBlocks(input: { approval: ApprovalRecord; toolCall: ToolCallRecord }): SlackBlock[] {
  const { approval, toolCall } = input;
  const payloadJson = JSON.stringify(redactJsonObject(toolCall.input), null, 2);

  return [
    {
      type: 'header',
      text: plainText('ActionProxy approval required'),
    },
    {
      type: 'section',
      fields: [
        markdownField('*Tool*\n' + toolCall.toolName),
        markdownField('*Risk*\n' + (toolCall.risk ?? 'unknown')),
        markdownField('*Requested by*\n' + toolCall.requestedBy),
        markdownField('*Agent*\n' + toolCall.agentId),
      ],
    },
    {
      type: 'section',
      text: mrkdwn('*Reason*\n' + toolCall.reason),
    },
    {
      type: 'section',
      text: mrkdwn('*Payload*\n```' + payloadJson + '```'),
    },
    {
      type: 'context',
      elements: [mrkdwn(`Approval ID: \`${approval.id}\``), mrkdwn(`Tool call ID: \`${toolCall.id}\``)],
    },
    {
      type: 'actions',
      block_id: `approval_actions_${approval.id}`,
      elements: [
        {
          type: 'button',
          action_id: SLACK_APPROVE_ACTION_ID,
          style: 'primary',
          text: plainText('Approve'),
          value: approval.id,
        },
        {
          type: 'button',
          action_id: SLACK_REJECT_ACTION_ID,
          style: 'danger',
          text: plainText('Reject'),
          value: approval.id,
        },
      ],
    },
  ];
}

function plainText(text: string): SlackText {
  return { emoji: false, text, type: 'plain_text' };
}

function mrkdwn(text: string): SlackText {
  return { text, type: 'mrkdwn' };
}

function markdownField(text: string): SlackText {
  return mrkdwn(text);
}
