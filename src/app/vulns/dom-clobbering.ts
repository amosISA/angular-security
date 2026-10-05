import { Component, afterNextRender, signal } from '@angular/core';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/**
 * CVE-2026-54267. Angular recovered its hydration state with
 * `document.getElementById('ng-state')`, and that lookup could be clobbered.
 *
 * The Angular-specific path is patched on 22.1.4, so this page demonstrates the
 * underlying browser behaviour — which is not patched and never will be,
 * because it is how the DOM works.
 */
@Component({
  selector: 'app-dom-clobbering',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="mechanism"
      heading="DOM clobbering the hydration state"
      summary="If an attacker controls an element id, they control what getElementById returns.
               Angular used a predictable id for its SSR state payload."
      cve="CVE-2026-54267"
      cveUrl="https://github.com/angular/angular/security/advisories/GHSA-rgjc-h3x7-9mwg"
    >
      <p>Angular ships hydration state to the browser inside the HTML, then reads it back by id:</p>
      <app-code-block [code]="lookupCode" language="html" label="Hydration state lookup code" />

      <p>
        Why <code>ng-state</code>? Because <code>APP_ID</code> defaults to the string
        <code>'ng'</code> and the element id is derived from it. That default is why the id is
        predictable in essentially every Angular app that has not changed it.
      </p>
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/application/application_tokens.ts#L39-L52"
          target="_blank"
          rel="noopener noreferrer"
          >APP_ID default</a
        >
        and
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/transfer_state.ts#L160-L175"
          target="_blank"
          rel="noopener noreferrer"
          >transfer-state element id</a
        >.
      </p>

      <h2>The browser behaviour</h2>
      <p class="hint">
        This injects two elements with the same id — an attacker-controlled <code>div</code> first,
        then the legitimate state <code>script</code> — and asks the DOM which one wins.
      </p>

      <button type="button" class="attack" (click)="run()">Clobber the lookup</button>

      @if (report(); as r) {
        <pre class="loot">{{ r }}</pre>
        <p>
          First in document order wins. If Angular reads that element, it parses the attacker's JSON
          as its own transfer cache — so <code>HttpClient</code> answers from the poisoned cache and
          never calls your backend. Nothing server-side sees the attack.
        </p>
      }

      <h2>Where the id comes from</h2>
      <p>
        The precondition is that your app binds untrusted data to an element <code>id</code>, which
        sounds exotic until you remember CMS-driven anchors and slugs:
      </p>
      <app-code-block [code]="vulnerableCode" language="html" label="Clobberable element id code" />

      <h2>The fix</h2>
      <p>Patched in 20.3.25, 21.2.17 and 22.0.1. Two hardening steps worth keeping anyway:</p>
      <app-code-block [code]="fixCode" label="Hydration APP_ID hardening code" />
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
    .loot {
      color: #ffd9d9;
      margin-top: 12px;
    }
  `,
})
export class DomClobbering {
  protected readonly report = signal<string | null>(null);
  private ready = false;

  protected readonly lookupCode = `<script type="application/json" id="ng-state">
  { "some-api-url": { "body": ... } }
</script>

// client bootstrap
JSON.parse(document.getElementById('ng-state').textContent);`;

  protected readonly vulnerableCode = `<!-- attacker supplies the slug, and therefore the id -->
<section [id]="cmsBlock.slug">…</section>

<!-- mitigated: a static prefix they cannot escape -->
<section [id]="'block-' + cmsBlock.slug">…</section>`;

  protected readonly fixCode = `import { APP_ID } from '@angular/core';
import { provideClientHydration } from '@angular/platform-browser';

providers: [
  // lookup becomes k7d92m-app-state instead of ng-state
  { provide: APP_ID, useValue: 'k7d92m-app' },
  provideClientHydration(),
];`;

  constructor() {
    afterNextRender(() => {
      this.ready = true;
    });
  }

  protected run() {
    if (!this.ready) return;

    // A deliberately namespaced id so this demo cannot disturb real hydration.
    const id = 'demo-clobber-state';
    document.getElementById(id)?.remove();
    document.querySelectorAll(`[data-demo-clobber]`).forEach((n) => n.remove());

    const host = document.createElement('div');
    host.setAttribute('data-demo-clobber', '');
    host.style.display = 'none';
    host.innerHTML =
      `<div id="${id}">{"\\/api\\/user\\/profile":{"body":{"role":"admin"}}}</div>` +
      `<script type="application/json" id="${id}">{"\\/api\\/user\\/profile":{"body":{"role":"user"}}}<\\/script>`;
    document.body.append(host);

    const winner = document.getElementById(id);
    const all = host.querySelectorAll(`#${id}`);

    this.report.set(
      [
        `elements carrying id="${id}": ${all.length}`,
        ``,
        `[0] <${all[0]?.tagName.toLowerCase()}>  ${all[0]?.textContent}   <-- attacker`,
        `[1] <${all[1]?.tagName.toLowerCase()}>  ${all[1]?.textContent}   <-- legitimate`,
        ``,
        `document.getElementById("${id}") returned: <${winner?.tagName.toLowerCase()}>`,
        `parsed role: ${JSON.parse(winner?.textContent ?? '{}')['/api/user/profile']?.body?.role}`,
      ].join('\n'),
    );

    host.remove();
  }
}
