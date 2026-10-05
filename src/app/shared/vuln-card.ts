import { Component, input } from '@angular/core';

export type Status = 'live' | 'mechanism' | 'blocked';

/**
 * Presentational shell shared by every demo, so each page reads the same way:
 * what it is, whether it actually works on this version, then the code.
 *
 * Container/presentational split: this component holds no state and injects
 * nothing. Every demo passes what it needs in.
 */
@Component({
  selector: 'app-vuln-card',
  template: `
    <article>
      <header>
        <span class="badge" [class]="status()">{{ label() }}</span>
        <h1>{{ heading() }}</h1>
        @if (cve(); as id) {
          <p class="cve">
            <a [href]="cveUrl()" target="_blank" rel="noopener noreferrer">{{ id }}</a>
          </p>
        }
      </header>

      <p class="lede">{{ summary() }}</p>

      <ng-content />
    </article>
  `,
  styles: `
    article {
      max-width: 820px;
    }
    header {
      border-bottom: 1px solid var(--line);
      padding-bottom: 14px;
      margin-bottom: 18px;
    }
    h1 {
      font-size: 24px;
      margin: 10px 0 0;
      line-height: 1.25;
    }
    .badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid currentColor;
    }
    .badge.live {
      color: var(--live);
    }
    .badge.mechanism {
      color: var(--mech);
    }
    .badge.blocked {
      color: var(--blocked);
    }
    .cve {
      margin: 8px 0 0;
      font-family: var(--mono);
      font-size: 12px;
    }
    .lede {
      color: var(--muted);
      margin: 0 0 22px;
    }
  `,
})
export class VulnCard {
  readonly heading = input.required<string>();
  readonly summary = input.required<string>();
  readonly status = input.required<Status>();
  readonly cve = input<string | null>(null);
  readonly cveUrl = input<string>('');

  label() {
    switch (this.status()) {
      case 'live':
        return 'Live demo pattern';
      case 'mechanism':
        return 'Patched — mechanism shown';
      case 'blocked':
        return 'Blocked in this build';
    }
  }
}
