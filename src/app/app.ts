import { Component, inject } from '@angular/core';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { Session } from './core/session';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <a class="skip" href="#main">Skip to content</a>

    <div class="shell">
      <nav aria-label="Demos">
        <a class="brand" routerLink="/">angular-security</a>
        <p class="meta">Angular 22.1.4 snapshot &middot; zoneless &middot; SSR</p>

        <p class="group">Baseline</p>
        <a routerLink="/sanitizer" routerLinkActive="on">What Angular blocks</a>

        <p class="group">Live demo patterns</p>
        <a routerLink="/xss-bypass" routerLinkActive="on">Sanitiser bypass</a>
        <a routerLink="/dom-injection" routerLinkActive="on">Direct DOM access</a>
        <a routerLink="/guard-bypass" routerLinkActive="on">Guards vs authorisation</a>
        <a routerLink="/supply-chain" routerLinkActive="on">npm supply chain</a>

        <p class="group">Patched &mdash; mechanism</p>
        <a routerLink="/transfer-cache" routerLinkActive="on">SSR transfer cache</a>
        <a routerLink="/hash-collision" routerLinkActive="on">32-bit cache keys</a>
        <a routerLink="/dom-clobbering" routerLinkActive="on">DOM clobbering</a>

        <p class="group">Fix it</p>
        <a routerLink="/defences" routerLinkActive="on">Defences</a>

        <div class="session">
          <p class="group">Demo session</p>
          <p class="session-help">
            Fake local token used only to demonstrate XSS theft and server-side authorisation.
          </p>
          <p class="token">{{ session.token() ?? 'signed out' }}</p>
          @if (session.token()) {
            <button type="button" (click)="session.signOut()">Sign out</button>
          } @else {
            <button type="button" (click)="session.signIn('tok_admin_9f2c')">
              Load demo admin token
            </button>
          }
        </div>
      </nav>

      <main id="main">
        <router-outlet />
      </main>
    </div>
  `,
  styles: `
    .skip {
      position: absolute;
      left: -9999px;
    }
    .skip:focus {
      left: 12px;
      top: 12px;
      z-index: 10;
      background: var(--panel-2);
      padding: 8px 12px;
      border-radius: 6px;
    }
    .shell {
      display: grid;
      grid-template-columns: 246px minmax(0, 1fr);
      min-height: 100vh;
    }
    nav {
      border-right: 1px solid var(--line);
      background: var(--panel);
      padding: 20px 16px;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }
    .brand {
      font-family: var(--mono);
      font-weight: 700;
      font-size: 14px;
      color: var(--text);
      text-decoration: none;
    }
    .meta {
      font-size: 11px;
      color: var(--muted);
      margin: 2px 0 14px;
      font-family: var(--mono);
    }
    .group {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--muted);
      margin: 16px 0 4px;
    }
    nav a:not(.brand) {
      font-size: 14px;
      color: var(--text);
      text-decoration: none;
      padding: 6px 9px;
      border-radius: 6px;
      border-left: 2px solid transparent;
    }
    nav a:not(.brand):hover {
      background: var(--panel-2);
    }
    nav a.on {
      background: var(--panel-2);
      border-left-color: var(--link);
      color: var(--link);
    }
    .session {
      margin-top: auto;
      padding-top: 16px;
      border-top: 1px solid var(--line);
    }
    .token {
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
      margin: 0 0 8px;
      word-break: break-all;
    }
    .session-help {
      margin: 0 0 8px;
      color: var(--muted);
      font-size: 11px;
      line-height: 1.4;
    }
    .session button {
      width: 100%;
      font-size: 13px;
    }
    main {
      padding: 32px 36px 80px;
      min-width: 0;
    }
    @media (max-width: 820px) {
      .shell {
        grid-template-columns: 1fr;
      }
      nav {
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }
      main {
        padding: 22px 18px 60px;
      }
    }
  `,
})
export class App {
  protected readonly session = inject(Session);
}
