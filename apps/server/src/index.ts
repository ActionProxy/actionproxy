import { buildApp } from './app';
import { loadConfig } from './config';

const config = loadConfig();

try {
  const app = await buildApp(config);
  await app.listen({ host: config.host, port: config.port });
  app.log.info(`ActionProxy server listening on http://${config.host}:${config.port}`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
}
