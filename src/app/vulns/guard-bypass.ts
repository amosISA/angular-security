import { Component, inject, signal } from '@angular/core';
import { FakeBackend } from '../core/fake-backend';
import { Session } from '../core/session';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/**
 * STAGE 3 of the chain. Not a CVE — a design mistake that turns any XSS into a
 * privilege escalation.
 */
@Component({
  selector: 'app-guard-bypass',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="live"
      heading="Route guards are UX, not authorisation"
      summary="A guard decides which screen a cooperative user sees. It cannot decide what an
               attacker is allowed to do, because the attacker does not have to use your app."
    >
      <p>Here is the guard that "protects" the admin area:</p>
      <app-code-block [code]="guardCode" label="Client-side route guard code" />

      <h2>Who are you right now?</h2>
      <p class="hint">
        These buttons do not contact an identity provider. They place a fixed teaching token in
        <code>localStorage</code> so the demo can compare a user token, an admin token, and no
        token.
      </p>
      <div class="row">
        <button type="button" (click)="signIn('tok_user_41ab')">Use demo user token</button>
        <button type="button" (click)="signIn('tok_admin_9f2c')">Use demo admin token</button>
        <button type="button" (click)="session.signOut()">Sign out</button>
      </div>
      <pre>token: {{ session.token() ?? '(none)' }}</pre>

      <h2>Attack: skip the app entirely</h2>
      <p class="hint">
        This calls the admin endpoint directly. No navigation happens, so
        <code>canActivate</code> never runs — exactly like <code>curl</code>, or like the injected
        payload on the XSS page.
      </p>
      <button type="button" class="attack" (click)="callDirectly()">POST /api/admin/payouts</button>

      @if (response(); as r) {
        <pre [class.loot]="r.startsWith('200')">{{ r }}</pre>
      }

      <h2>What actually saved you</h2>
      <p>
        As a <code>user</code> you got <code>403</code> — and notice <em>why</em>. Not because the
        guard blocked anything; it never executed. Because
        <code>FakeBackend.requireAdmin()</code> checked the token server-side.
      </p>
      <p>
        Now imagine that server check is missing, because the team believed the guard was the
        security boundary. Then this button returns <code>200</code> for anyone, and the only thing
        standing in front of your payouts endpoint is a TypeScript function that the attacker
        downloaded, read, and skipped.
      </p>

      <h2>Server audit log</h2>
      <p class="hint">What the backend actually received. This is the only record that matters.</p>
      <pre>{{
        backend.auditLog().length
          ? backend.auditLog().join(
              '
'
            )
          : '(no requests yet)'
      }}</pre>
      <button type="button" (click)="backend.clearLog()">Clear log</button>

      <h2>The rule</h2>
      <p>
        Keep the guard — it is good UX. Just never let it be the only check. And treat anything you
        decode from a JWT in the browser as a rendering hint, never as a permission.
      </p>
    </app-vuln-card>
  `,
  styles: `
    h2 {
      font-size: 15px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      margin: 26px 0 8px;
    }
    .hint {
      color: var(--muted);
      font-size: 14px;
      margin: 0 0 10px;
    }
    .row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 10px;
    }
    .loot {
      color: #ffd9d9;
    }
  `,
})
export class GuardBypass {
  protected readonly session = inject(Session);
  protected readonly backend = inject(FakeBackend);
  protected readonly response = signal<string | null>(null);

  protected readonly guardCode = `export const adminGuard: CanActivateFn = () =>
  inject(Session).role() === 'admin';   // runs in the browser, on the attacker's machine

// routes
{ path: 'admin', component: AdminPanel, canActivate: [adminGuard] }`;

  protected signIn(token: string) {
    this.session.signIn(token);
    this.response.set(null);
  }

  protected callDirectly() {
    const res = this.backend.requireAdmin(this.session.readable());
    this.response.set(`${res.status} ${res.body}`);
  }
}
