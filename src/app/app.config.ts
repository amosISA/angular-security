import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter, withInMemoryScrolling } from '@angular/router';
import { provideHttpClient, withFetch } from '@angular/common/http';
import { provideClientHydration } from '@angular/platform-browser';
import { routes } from './app.routes';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withInMemoryScrolling({ scrollPositionRestoration: 'top' })),
    provideHttpClient(withFetch()),

    /**
     * Hydration is left ON, with the HTTP transfer cache at its default, so the
     * /transfer-cache demo has something real to show you.
     *
     * In an app handling per-user data you would reach for
     * `provideClientHydration(withNoHttpTransferCache())`, or opt out per
     * request with `{ transferCache: false }`.
     */
    provideClientHydration(),
  ],
};
