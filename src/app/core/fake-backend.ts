import { Injectable, signal } from '@angular/core';

/**
 * Stands in for a real backend.
 *
 * The important part is `requireAdmin`: this is the ONLY authorisation check
 * that matters. It lives here, on the "server" side of the boundary. The
 * Angular route guard in the client is a separate thing and cannot replace it.
 *
 * `auditLog` exists so the demos can show what the server actually saw,
 * which is usually the thing that makes the penetration click.
 */
@Injectable({ providedIn: 'root' })
export class FakeBackend {
  /** Tokens the "server" considers valid, mapped to a role. */
  private readonly tokens = new Map<string, 'admin' | 'user'>([
    ['tok_admin_9f2c', 'admin'],
    ['tok_user_41ab', 'user'],
  ]);

  readonly auditLog = signal<readonly string[]>([]);

  /** A per-user, credentialed response. The kind you must not transfer-cache. */
  getProfile(token: string | null) {
    const role = token ? this.tokens.get(token) : undefined;
    this.log(`GET /api/profile (token=${token ?? 'none'})`);
    if (!role) return { error: 'unauthenticated' as const };
    return {
      email: role === 'admin' ? 'admin@acme.internal' : 'user@acme.internal',
      role,
      // Deliberately sensitive: this is what leaks if you cache credentialed
      // responses into the SSR payload.
      billingId: role === 'admin' ? 'cus_9Xk22admin' : 'cus_41ab7user',
    };
  }

  /**
   * The server-side authorisation check. Note that it does not care at all
   * whether a route guard ran in the browser.
   */
  requireAdmin(token: string | null) {
    const role = token ? this.tokens.get(token) : undefined;
    this.log(`POST /api/admin/payouts (token=${token ?? 'none'}) -> role=${role ?? 'none'}`);
    if (role !== 'admin') {
      return { ok: false as const, status: 403, body: 'Forbidden' };
    }
    return {
      ok: true as const,
      status: 200,
      body: 'Payout of 40,000 EUR approved.',
    };
  }

  private log(line: string) {
    const stamp = new Date().toISOString().slice(11, 19);
    this.auditLog.update((l) => [...l, `${stamp}  ${line}`]);
  }

  clearLog() {
    this.auditLog.set([]);
  }
}
