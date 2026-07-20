import type { FastifyInstance } from 'fastify';
import type { ActionProxyService } from '../services/action-gate';
import {
  registerTelegramWebhookRoutes,
  type TelegramWebhookRouteOptions,
} from '../integrations/telegram/telegram-routes';

export async function registerTelegramRoutes(
  app: FastifyInstance,
  actionProxy: ActionProxyService,
  options: TelegramWebhookRouteOptions,
): Promise<void> {
  await registerTelegramWebhookRoutes(app, actionProxy, options);
}
