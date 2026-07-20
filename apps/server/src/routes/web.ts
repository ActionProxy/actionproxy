import fs from 'node:fs/promises';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';

const contentTypes: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
};

export async function registerWebAppRoutes(app: FastifyInstance, webDistPath: string | undefined): Promise<void> {
  if (!webDistPath || !(await fileExists(path.join(webDistPath, 'index.html')))) return;
  const root = path.resolve(webDistPath);

  app.get('/*', async (request, reply) => {
    const pathname = new URL(request.url, 'http://actionproxy.local').pathname;
    if (pathname === '/health' || pathname.startsWith('/v1/')) {
      return reply.status(404).send({ error: 'not_found' });
    }

    const candidate = safeAssetPath(root, pathname);
    const filePath = candidate && (await fileExists(candidate)) ? candidate : path.join(root, 'index.html');
    const body = await fs.readFile(filePath);
    const extension = path.extname(filePath);
    reply.header('cache-control', filePath.endsWith('index.html') ? 'no-store' : 'public, max-age=31536000, immutable');
    reply.header(
      'content-security-policy',
      "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'self'",
    );
    return reply.type(contentTypes[extension] ?? 'application/octet-stream').send(body);
  });
}

function safeAssetPath(root: string, pathname: string): string | undefined {
  const relativePath = pathname === '/' ? 'index.html' : decodeURIComponent(pathname.replace(/^\/+/, ''));
  const resolved = path.resolve(root, relativePath);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`) ? resolved : undefined;
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    const stats = await fs.stat(filePath);
    return stats.isFile();
  } catch {
    return false;
  }
}
