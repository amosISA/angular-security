import {
  AngularNodeAppEngine,
  createNodeRequestHandler,
  isMainModule,
  writeResponseToNodeResponse,
} from '@angular/ssr/node';
import express from 'express';
import { join } from 'node:path';

const browserDistFolder = join(import.meta.dirname, '../browser');

const app = express();
const angularApp = new AngularNodeAppEngine();

/**
 * Demo API.
 *
 * `/api/profile` is deliberately credentialed and per-user. It is the shape of
 * response that must never end up in the SSR transfer cache, because the
 * rendered HTML can be stored by any shared cache in front of the app.
 */
app.get('/api/profile', (req, res) => {
  const token = req.header('x-demo-token') ?? req.query['token'] ?? null;
  const known: Record<string, { email: string; role: string; billingId: string }> = {
    tok_admin_9f2c: {
      email: 'admin@acme.internal',
      role: 'admin',
      billingId: 'cus_9Xk22admin',
    },
    tok_user_41ab: {
      email: 'user@acme.internal',
      role: 'user',
      billingId: 'cus_41ab7user',
    },
  };

  const profile = typeof token === 'string' ? known[token] : undefined;
  res.json(
    profile ?? {
      email: 'anonymous@example.com',
      role: 'guest',
      billingId: 'none',
    },
  );
});

/**
 * Serve static files from /browser
 */
app.use(
  express.static(browserDistFolder, {
    maxAge: '1y',
    index: false,
    redirect: false,
  }),
);

/**
 * Strict CSP, switched on with HARDENED=1.
 *
 * Run the app both ways and compare. With this header set, the XSS payloads on
 * /xss-bypass and /dom-injection stop working — the sanitiser bypass is still
 * there in the code, it just no longer buys the attacker anything. That is the
 * whole argument for CSP: it decides whether a bypass is a vulnerability or a
 * curiosity.
 *
 * Two honest notes about this header:
 *
 * 1. `script-src 'self'` is what kills the payloads. Inline event handlers like
 *    `onerror=` need 'unsafe-inline' to run, and we are not granting it.
 *    Angular's own bundles are external files, so they load normally.
 *
 * 2. `style-src` still allows 'unsafe-inline' here, because Angular injects
 *    styles at runtime and this demo has no per-request nonce plumbing. In a
 *    real SSR app you generate a nonce per response and provide it through the
 *    CSP_NONCE token, then drop 'unsafe-inline' entirely. Note you cannot use
 *    the builder's `autoCsp` for this: it is hash-based and the builder rejects
 *    combining it with SSR ("Cannot set both SSR and auto-CSP at the same
 *    time"). Hashes are for static builds, nonces are for SSR.
 */
app.use((_req, res, next) => {
  if (process.env['HARDENED']) {
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  }
  next();
});

/**
 * Handle all other requests by rendering the Angular application.
 */
app.use((req, res, next) => {
  angularApp
    .handle(req)
    .then((response) => (response ? writeResponseToNodeResponse(response, res) : next()))
    .catch(next);
});

/**
 * Start the server if this module is the main entry point, or it is ran via PM2.
 * The server listens on the port defined by the `PORT` environment variable, or defaults to 4000.
 */
if (isMainModule(import.meta.url) || process.env['pm_id']) {
  const port = process.env['PORT'] || 4000;
  app.listen(port, (error) => {
    if (error) {
      throw error;
    }

    console.log(`Node Express server listening on http://localhost:${port}`);
  });
}

/**
 * Request handler used by the Angular CLI (for dev-server and during build) or Firebase Cloud Functions.
 */
export const reqHandler = createNodeRequestHandler(app);
