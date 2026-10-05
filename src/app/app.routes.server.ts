import { RenderMode, ServerRoute } from '@angular/ssr';

/**
 * Server rendering, not prerendering. The transfer cache demo needs a real
 * per-request render so there is something to serialise into the HTML.
 */
export const serverRoutes: ServerRoute[] = [
  {
    path: '**',
    renderMode: RenderMode.Server,
  },
];
