import { Injectable, PLATFORM_ID, inject, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';

const KEY = 'demo.auth.token';

/**
 * Deliberately insecure session store: the access token lives in
 * `localStorage`, which is exactly what the "just use localStorage" advice
 * tells you to do.
 *
 * localStorage is readable by ANY JavaScript running on this origin. So the
 * safety of this design is entirely equivalent to the claim "this app has no
 * XSS" — and /xss-bypass demonstrates that claim failing.
 *
 * The real fix is not a different Web Storage API (sessionStorage is just as
 * readable). It is to stop holding the credential in JavaScript at all: keep
 * it server-side behind an HttpOnly, Secure, SameSite cookie (BFF pattern).
 */
@Injectable({ providedIn: 'root' })
export class Session {
  private readonly isBrowser = isPlatformBrowser(inject(PLATFORM_ID));

  /** Mirrors localStorage so templates can react to it. */
  readonly token = signal<string | null>(null);

  constructor() {
    if (this.isBrowser) {
      this.token.set(localStorage.getItem(KEY));
    }
  }

  signIn(token: string) {
    if (this.isBrowser) localStorage.setItem(KEY, token);
    this.token.set(token);
  }

  signOut() {
    if (this.isBrowser) localStorage.removeItem(KEY);
    this.token.set(null);
  }

  /** What an injected script can trivially read. Nothing protects this. */
  readable(): string | null {
    return this.isBrowser ? localStorage.getItem(KEY) : null;
  }
}
