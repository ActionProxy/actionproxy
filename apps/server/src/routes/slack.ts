import type { FastifyInstance } from 'fastify';
import { registerSlackInteractionRoutes, type SlackInteractionRouteOptions } from '../integrations/slack/slack-routes';
import type { ActionProxyService } from '../services/action-gate';

export async function registerSlackRoutes(
  app: FastifyInstance,
  actionProxy: ActionProxyService,
  options: SlackInteractionRouteOptions,
): Promise<void> {
  await registerSlackInteractionRoutes(app, actionProxy, options);
}
