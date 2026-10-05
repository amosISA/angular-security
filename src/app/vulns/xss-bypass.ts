import { Component, afterNextRender, computed, inject, signal } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { FakeBackend } from '../core/fake-backend';
import { Session } from '../core/session';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

declare global {
  interface Window {
    __demoExfiltrate?: (label: string, value: string) => void;
  }
}

/**
 * STAGE 1 of the attack chain, and the only XSS on this page that is a real,
 * present-day, fully-patched-Angular vulnerability.
 *
 * Nothing here is an Angular bug. Angular sanitises `[innerHTML]` correctly.
 * We are explicitly telling it not to.
 */
@Component({
  selector: 'app-xss-bypass',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="live"
      heading="bypassSecurityTrustHtml on untrusted input"
      summary="Not a framework bug. The sanitiser works — we switch it off by hand, which is
               the most common serious XSS in real Angular codebases."
    >
      <p>
        Imagine <code>bio</code> is a rich-text field from a CMS. Someone decided the sanitiser was
        "breaking their formatting", so they reached for the bypass:
      </p>

      <app-code-block [code]="vulnerableCode" label="Unsafe DomSanitizer bypass code" />
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/platform-browser/src/security/dom_sanitization_service.ts#L121-L163"
          target="_blank"
          rel="noopener noreferrer"
          >DomSanitizer bypass API</a
        >.
      </p>

      <h2>Attack</h2>
      <p class="hint">
        The payload uses a hidden <code>&lt;img&gt;</code> with an invalid <code>src</code>. Its
        <code>onerror</code> handler still runs immediately, without leaving a broken-image icon in
        the demo. Note it is <em>not</em> a <code>&lt;script&gt;</code> tag — those do not execute
        when inserted via <code>innerHTML</code>, which is why every real payload looks like this
        instead.
      </p>

      <label for="payload" class="sr-only">Attacker payload</label>
      <textarea id="payload" rows="4" [value]="draft()" (input)="onInput($event)"></textarea>

      <div class="row">
        <button type="button" class="attack" (click)="render()">Render as trusted HTML</button>
        <button type="button" (click)="reset()">Reset</button>
      </div>

      <h2>Rendered output</h2>
      <div class="stage" [innerHTML]="trusted()"></div>

      <h2>Attacker console</h2>
      <p class="hint">
        What the injected script managed to read. In a real attack this would be a
        <code>fetch()</code> to the attacker's server instead of a panel on your own page.
      </p>
      <pre class="loot">{{
        loot().length
          ? loot().join(
              '
'
            )
          : '(nothing stolen yet)'
      }}</pre>

      <h2>The fix</h2>
      <p>
        There isn't a safer way to call the bypass. The fix is to not call it: bind the value
        normally and let the sanitiser do its job.
      </p>
      <app-code-block [code]="fixedCode" label="Safe Angular binding code" />
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/platform-browser/src/security/dom_sanitization_service.ts#L193-L206"
          target="_blank"
          rel="noopener noreferrer"
          >HTML sanitisation path</a
        >.
      </p>
      <p>
        If you genuinely need to keep some markup, sanitise to an allowlist of tags on the server
        before it ever reaches the template — and remember a strict CSP would have stopped the
        inline <code>onerror</code> from running at all.
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
      margin-top: 10px;
    }
    .stage {
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 14px;
      min-height: 52px;
      background: var(--panel);
    }
    .loot {
      color: #ffd9d9;
    }
  `,
})
export class XssBypass {
  private readonly sanitizer = inject(DomSanitizer);
  private readonly session = inject(Session);
  private readonly backend = inject(FakeBackend);

  /** A payload that walks the whole chain: read the token, then use it. */
  private readonly defaultPayload =
    `<img hidden src=x onerror="__demoExfiltrate('localStorage token', ` +
    `localStorage.getItem('demo.auth.token') || 'none')">` +
    `<strong>Totally normal bio.</strong>`;

  protected readonly draft = signal(this.defaultPayload);
  protected readonly submitted = signal<string>('<em>No bio yet.</em>');
  protected readonly loot = signal<readonly string[]>([]);

  /**
   * The bug, in one expression. Angular has no way to know this string is
   * hostile — we have asserted that it isn't.
   */
  protected readonly trusted = computed(() =>
    this.sanitizer.bypassSecurityTrustHtml(this.submitted()),
  );

  protected readonly vulnerableCode = `// component
readonly trusted = computed(() =>
  this.sanitizer.bypassSecurityTrustHtml(this.bio()),  // <- the whole bug
);

// template
<div [innerHTML]="trusted()"></div>`;

  protected readonly fixedCode = `// template — Angular strips the onerror handler for you
<div [innerHTML]="bio()"></div>`;

  constructor() {
    // Browser-only: give the payload something observable to call instead of
    // making a real outbound request.
    afterNextRender(() => {
      window.__demoExfiltrate = (label, value) => {
        this.loot.update((l) => [...l, `stole  ${label}: ${value}`]);

        // Stage 3: the stolen token is enough to call an admin-only endpoint.
        // No route guard is involved, because no route is involved.
        const res = this.backend.requireAdmin(this.session.readable());
        this.loot.update((l) => [
          ...l,
          `replayed token against POST /api/admin/payouts -> ${res.status} ${res.body}`,
        ]);
      };
    });
  }

  protected onInput(event: Event) {
    this.draft.set((event.target as HTMLTextAreaElement).value);
  }

  protected render() {
    this.submitted.set(this.draft());
  }

  protected reset() {
    this.loot.set([]);
    this.submitted.set('<em>No bio yet.</em>');
    this.draft.set(this.defaultPayload);
  }
}
