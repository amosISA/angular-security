import { Component, afterNextRender, signal } from '@angular/core';
import { httpResource } from '@angular/common/http';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

interface Profile {
  email: string;
  role: string;
  billingId: string;
}

/**
 * CVE-2026-50170 was the framework bug: the transfer cache ignored
 * `withCredentials` and the `Cookie` header, so per-user responses were
 * serialised into the page.
 *
 * That specific flaw is patched on 22.1.4: authenticated and credentialed
 * requests are excluded by default. This page uses an anonymous demo response
 * to show the transfer-state mechanism without pretending the old bug is live.
 */
@Component({
  selector: 'app-transfer-cache',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="mechanism"
      [heading]="
        isStaticPages
          ? 'SSR transfer cache: local demo required'
          : 'Your SSR payload is in the page'
      "
      [summary]="
        isStaticPages
          ? 'This static demo makes no API request. Run the SSR build locally to inspect the real payload.'
          : 'Hydration ships HTTP responses made during SSR inside the HTML. Several advisories came out of that boundary.'
      "
      cve="CVE-2026-50170"
      cveUrl="https://github.com/angular/angular/security/advisories/GHSA-q6f4-qqrg-jv6x"
    >
      @if (isStaticPages) {
        <p class="public-note">
          You are viewing the static, client-only GitHub Pages demo. It does not call
          <code>/api/profile</code>, and there is no SSR transfer-cache payload in this page. To
          observe the real payload locally, run
          <code>pnpm build &amp;&amp; pnpm serve:ssr</code> and open this route on
          <code>http://localhost:4000</code>.
        </p>

        <h2>What the public demo sees</h2>
        <pre>{{ profileText() }}</pre>

        <h2>Why there is no payload here</h2>
        <pre class="loot">{{ statePayload() }}</pre>

        <h2>Cache-key observation</h2>
        <pre>{{ keyAnalysis() }}</pre>
      } @else {
        <p>
          This component fetches <code>/api/profile</code>. Because
          <code>provideClientHydration()</code> is enabled, the response made during server
          rendering was cached and embedded in the document you are reading. The request is
          intentionally anonymous; patched Angular excludes requests with authentication headers,
          cookies, or credentials by default.
        </p>
        <p class="hint">
          Angular source:
          <a
            href="https://github.com/angular/angular/blob/v22.1.4/packages/platform-browser/src/hydration.ts#L192-L244"
            target="_blank"
            rel="noopener noreferrer"
            >provideClientHydration and transfer-cache setup</a
          >,
          <a
            href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/transfer_cache.ts#L147-L177"
            target="_blank"
            rel="noopener noreferrer"
            >default request eligibility</a
          >.
        </p>

        <h2>What the component sees</h2>
        <pre>{{ profileText() }}</pre>

        <h2>What is actually in your HTML</h2>
        <p class="hint">
          Read straight out of the DOM at hydration time. This is not a reconstruction — it is the
          transfer cache script element the server sent you. View source and you will find it there
          too.
        </p>
        <pre class="loot">{{ statePayload() }}</pre>

        <h2>The fix, visible in your own page</h2>
        <p class="hint">
          Look at the cache key above. Count the characters. This is the patch for
          <a
            href="https://github.com/angular/angular/security/advisories/GHSA-39pv-4j6c-2g6v"
            target="_blank"
            rel="noopener noreferrer"
            >CVE-2026-54266</a
          >
          sitting in front of you.
        </p>
        <pre>{{ keyAnalysis() }}</pre>
        <p class="hint">
          Angular source:
          <a
            href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/transfer_cache.ts#L600-L625"
            target="_blank"
            rel="noopener noreferrer"
            >SHA-256 cache-key generation</a
          >.
        </p>
      }

      <h2>Why that became a cluster of advisories</h2>
      <p>
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-q6f4-qqrg-jv6x"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2026-50170</a
        >
        — the cache did not check <code>withCredentials</code> or <code>Cookie</code>, so
        authenticated responses landed here. Harmless on its own; a data breach the moment a CDN or
        reverse proxy caches the HTML and serves it to the next visitor.
      </p>
      <p>
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-39pv-4j6c-2g6v"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2026-54266</a
        >
        — the keys were 32-bit hashes. See the collision demo, which finds one in milliseconds.
      </p>
      <p>
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-rgjc-h3x7-9mwg"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2026-54267</a
        >
        — the element id was guessable, so the lookup could be clobbered and the cache poisoned.
      </p>
      <p>
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-jhpw-976m-542j"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2026-68945</a
        >
        — repeated query parameters could produce ambiguous cache-key material. Fixed in Angular
        22.0.2.
      </p>
      <p>
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-p297-fm68-3q8c"
          target="_blank"
          rel="noopener noreferrer"
          >GHSA-p297-fm68-3q8c</a
        >
        — hierarchical clients using <code>withRequestsMadeViaParent()</code> could cache a response
        after a parent interceptor added credentials. Fixed in Angular 22.1.1.
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/provider.ts#L260-L297"
          target="_blank"
          rel="noopener noreferrer"
          >Angular source</a
        >.
      </p>

      <h2>The decision that is yours</h2>
      <p>
        Patched Angular excludes authenticated or credentialed requests by default. It still cannot
        infer every business-sensitive anonymous response or protect every future custom client
        configuration. Explicitly opt sensitive endpoints out when the browser does not need the SSR
        copy:
      </p>
      <app-code-block [code]="fixCode" label="Transfer cache opt-out code" />
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/request.ts#L100-L140"
          target="_blank"
          rel="noopener noreferrer"
          >per-request transferCache option</a
        >
        and
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/platform-browser/src/hydration.ts#L67-L79"
          target="_blank"
          rel="noopener noreferrer"
          >withNoHttpTransferCache</a
        >.
      </p>
      <p class="hint">
        And if you put a shared cache in front of an SSR app, the <code>Cache-Control</code> and
        <code>Vary</code> headers stop being an infra detail and become part of your security model.
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
    .public-note {
      padding: 14px 16px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: color-mix(in srgb, var(--accent) 10%, transparent);
    }
    .loot {
      color: #ffd9d9;
      white-space: pre-wrap;
      word-break: break-all;
    }
  `,
})
export class TransferCache {
  protected readonly isStaticPages =
    typeof window !== 'undefined' && window.location.hostname.endsWith('.github.io');

  /** Runs during local SSR, but is disabled on the static GitHub Pages host. */
  private readonly profile = httpResource<Profile>(() =>
    this.isStaticPages ? undefined : '/api/profile',
  );

  protected readonly statePayload = signal('(reading the document…)');
  protected readonly keyAnalysis = signal('(reading the document…)');

  protected profileText() {
    if (this.isStaticPages) return 'Request disabled on the static GitHub Pages demo.';
    if (this.profile.isLoading()) return 'loading…';
    if (this.profile.error()) return `error: ${String(this.profile.error())}`;
    return JSON.stringify(this.profile.value(), null, 2);
  }

  protected readonly fixCode = `// per request — keep this response out of the page
this.http.get('/api/profile', { transferCache: false });

// or switch the whole feature off
import { provideClientHydration, withNoHttpTransferCache } from '@angular/platform-browser';
providers: [provideClientHydration(withNoHttpTransferCache())];`;

  constructor() {
    afterNextRender(() => {
      if (this.isStaticPages) {
        this.statePayload.set(
          'No SSR state is expected: GitHub Pages serves this application as static files.',
        );
        this.keyAnalysis.set(
          'Run `pnpm build && pnpm serve:ssr` locally to inspect the real SHA-256 cache key.',
        );
        return;
      }

      // APP_ID defaults to 'ng', so the element is #ng-state unless changed.
      const el =
        document.getElementById('ng-state') ??
        document.querySelector('script[type="application/json"][id$="-state"]');

      this.statePayload.set(
        el?.textContent?.trim()
          ? `#${el.id}\n\n${el.textContent.trim()}`
          : 'No transfer cache found in the document.\n\n' +
              'Expected when running `ng serve` in client-only mode, or if hydration is off.\n' +
              'Run: pnpm build && pnpm serve:ssr',
      );

      // Pull the cache key out and measure it, so the fix is observed rather
      // than taken on trust.
      try {
        const parsed = JSON.parse(el?.textContent ?? '{}') as Record<string, unknown>;
        const key = Object.keys(parsed).find((k) => k !== '__nghData__');
        if (!key) {
          this.keyAnalysis.set('No cached HTTP entry found in the payload.');
          return;
        }
        const isHex64 = /^[0-9a-f]{64}$/.test(key);
        this.keyAnalysis.set(
          [
            `cache key:  ${key}`,
            `length:     ${key.length} characters`,
            `bits:       ${isHex64 ? '256 (SHA-256 hex)' : 'not a 64-char hex digest'}`,
            ``,
            isHex64
              ? 'Patched. Before 20.3.25 / 21.2.17 / 22.0.1 this was a 32-bit\n' +
                'integer, and /hash-collision finds a collision for one of those\n' +
                'in milliseconds.'
              : 'This does not look like the patched SHA-256 format. Check your version.',
          ].join('\n'),
        );
      } catch {
        this.keyAnalysis.set('Could not parse the transfer cache payload.');
      }
    });
  }
}
