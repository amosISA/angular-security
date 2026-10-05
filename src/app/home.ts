import { Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-home',
  imports: [RouterLink],
  template: `
    <div class="wrap">
      <h1>Angular security, one vulnerability at a time</h1>
      <p class="lede">
        Angular {{ version }}, zoneless, with safe demonstrations of real security boundaries. Every
        demo is labelled with whether it actually works on this version, because that turns out to
        be the most interesting thing about the topic.
      </p>

      <p class="warning">
        This public GitHub Pages demo is a static, client-only build and is safe to browse. The
        repository intentionally keeps a vulnerable Angular 22.1.4 SSR snapshot for local teaching:
        do not deploy that pinned SSR server publicly. The malformed-DOCTYPE denial of service is
        fixed in 22.1.6.
      </p>

      <section class="legend">
        <p>
          <span class="k live">Live</span> A developer-created vulnerability that works in this
          versioned demo. It is not a claim that 22.1.4 is fully patched today.
        </p>
        <p>
          <span class="k mechanism">Mechanism</span> The framework bug is patched, so the underlying
          mechanism is demonstrated instead.
        </p>
        <p>
          <span class="k blocked">Blocked</span> A payload this installed build stops. Included so
          you can see the default working.
        </p>
      </section>

      <h2>The chain</h2>
      <p class="lede">
        Individually these look survivable. The point is that they compose. Here is one bug becoming
        a breach, and every stage is clickable.
      </p>

      <ol class="chain">
        <li>
          <h3><a routerLink="/xss-bypass">A developer switches off the sanitiser</a></h3>
          <p>
            A CMS bio field is rendered with <code>bypassSecurityTrustHtml</code> because the
            sanitiser was "breaking the formatting". An attacker stores
            <code>&lt;img src=x onerror=…&gt;</code> in their profile.
          </p>
          <p class="gate">Would have been stopped by: not calling the bypass. Or a strict CSP.</p>
        </li>
        <li>
          <h3><a routerLink="/xss-bypass">The payload reads the access token</a></h3>
          <p>
            The token is in <code>localStorage</code>, which any script on the origin can read. One
            line: <code>localStorage.getItem('demo.auth.token')</code>.
          </p>
          <p class="gate">Would have been stopped by: an HttpOnly cookie the script cannot read.</p>
        </li>
        <li>
          <h3><a routerLink="/guard-bypass">It calls the admin endpoint directly</a></h3>
          <p>
            No navigation happens, so <code>canActivate</code> never runs. The route guard was never
            in the request path — it only ever decided which screen to show.
          </p>
          <p class="gate">
            Would have been stopped by: the server checking the role. It does here.
          </p>
        </li>
        <li>
          <h3>The token outlives the XSS</h3>
          <p>
            Because a bearer token was stolen rather than a session used, the attacker keeps working
            from their own machine after the victim closes the tab.
          </p>
          <p class="gate">This is the whole argument against holding credentials in JavaScript.</p>
        </li>
      </ol>

      <p class="note">
        Three separate decisions had to be wrong at once, and each one on its own looked like a
        reasonable trade. That is what a real incident looks like.
      </p>

      <h2>Everything else</h2>
      <ul class="index">
        <li><a routerLink="/sanitizer">What Angular blocks on its own</a> — the control group</li>
        <li>
          <a routerLink="/dom-injection">Direct DOM access</a> — how to lose the sanitiser without
          calling a bypass
        </li>
        <li>
          <a routerLink="/transfer-cache">The SSR transfer cache</a> — your API responses, in the
          page
        </li>
        <li>
          <a routerLink="/hash-collision">32-bit cache keys</a> — a real collision, found in your
          browser
        </li>
        <li><a routerLink="/dom-clobbering">DOM clobbering</a> — poisoning hydration state</li>
        <li>
          <a routerLink="/supply-chain">The npm worm</a> — the attack that ignores your framework
        </li>
        <li><a routerLink="/defences">Defences</a> — what to turn on, in order</li>
      </ul>

      <h2>Not demonstrated here</h2>
      <p class="lede">
        This is a curated teaching app, not a catalogue of every possible Angular vulnerability.
        These advisories are documented rather than turned into live exploits.
      </p>
      <ul class="index">
        <li>
          <strong>i18n ICU XSS</strong> (CVE-2026-27970) — needs a localised build and a hostile
          <code>.xlf</code> from a translation vendor. The lesson survives without a demo: your
          translation files have the privileges of source code and none of the review.
        </li>
        <li>
          <strong>SSR raw-content serialisation</strong> (CVE-2026-69149) — domino failed to escape
          text inside <code>&lt;noscript&gt;</code> and friends, triggered by critical CSS inlining
          re-parsing the HTML. Patched, and reproducing it means pinning a vulnerable version.
        </li>
        <li>
          <strong>Later SSR serializer and URL issues</strong> — processing-instruction XSS,
          template-fragment XSS, and URL-resolution SSRF are fixed in Angular 22.1.4. Their
          preconditions are narrow and a safe page demo would teach less than the advisories.
        </li>
        <li>
          <strong>Malformed-DOCTYPE SSR denial of service</strong> (GHSA-f67j-2jqw-jpq7) — the
          installed <code>@angular/platform-server</code> 22.1.4 is affected. The demo does not run
          a payload that intentionally locks the Node process; Angular 22.1.6 contains the fix.
        </li>
      </ul>

      <h2>Primary sources</h2>
      <p class="lede">
        Every framework vulnerability named in this lab links to the Angular team's advisory. Those
        advisories — not the demo copy — are the authority for affected versions, prerequisites,
        impact, and patches. Framework implementation claims also link to immutable, versioned
        source lines. Last checked 4 October 2026.
      </p>
      <details class="sources">
        <summary>Open the complete source index</summary>
        <h3>Angular security model</h3>
        <ul>
          <li><a href="https://angular.dev/best-practices/security">Angular security guide</a></li>
          <li>
            <a href="https://angular.dev/guide/routing/route-guards">Angular route guard guide</a>
          </li>
          <li><a href="https://angular.dev/guide/ssr">Angular SSR guide</a></li>
        </ul>
        <h3>Angular v22.1.4 source code</h3>
        <ul>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/sanitization/dom_security_schema.ts#L18-L26"
              >SecurityContext enum</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/platform-browser/src/security/dom_sanitization_service.ts#L100-L163"
              >DomSanitizer and bypass methods</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/compiler/src/schema/dom_security_schema.ts#L38-L56"
              >Compiler security schema</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/transfer_cache.ts#L147-L177"
              >Transfer-cache request eligibility</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/transfer_cache.ts#L600-L625"
              >SHA-256 transfer-cache keys</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/transfer_state.ts#L160-L175"
              >Transfer-state element lookup</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/application/application_tokens.ts#L39-L52"
              >APP_ID default</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/application/application_tokens.ts#L110-L146"
              >CSP_NONCE token</a
            >
          </li>
        </ul>
        <h3>Angular CLI v22.1.6 source code</h3>
        <ul>
          <li>
            <a
              href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/builders/application/schema.json#L50-L75"
              >autoCsp and allowedHosts builder options</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/utils/index-file/index-html-generator.ts#L104-L108"
              >autoCsp incompatibility with SSR and prerendering</a
            >
          </li>
          <li>
            <a
              href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/builders/application/schema.json#L479-L483"
              >Subresource Integrity builder option</a
            >
          </li>
        </ul>
        <h3>Sanitisation, templates, and i18n</h3>
        <ul>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-v4hv-rgfq-gp49"
              >CVE-2025-66412</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-jrmj-c5cx-3cw6"
              >CVE-2026-22610</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-f3m7-gqxr-g87x"
              >CVE-2026-50557</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-prjf-86w9-mfqv"
              >CVE-2026-27970</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-jj27-h5hq-8x99"
              >CVE-2026-69151</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-hh8m-fm6v-7cvg"
              >GHSA-hh8m-fm6v-7cvg</a
            >
          </li>
        </ul>
        <h3>SSR, transfer cache, and service worker</h3>
        <ul>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-vpx6-8pjr-4g3v"
              >CVE-2026-69149</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-q6f4-qqrg-jv6x"
              >CVE-2026-50170</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-39pv-4j6c-2g6v"
              >CVE-2026-54266</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-rgjc-h3x7-9mwg"
              >CVE-2026-54267</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-jhpw-976m-542j"
              >CVE-2026-68945</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-p297-fm68-3q8c"
              >GHSA-p297-fm68-3q8c</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-j3r3-mxqp-r2p4"
              >GHSA-j3r3-mxqp-r2p4</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-v3p8-whq6-r5jg"
              >GHSA-v3p8-whq6-r5jg</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-f6mr-pjwc-34m4"
              >GHSA-f6mr-pjwc-34m4</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-f67j-2jqw-jpq7"
              >GHSA-f67j-2jqw-jpq7</a
            >
          </li>
          <li>
            <a href="https://github.com/angular/angular/security/advisories/GHSA-qxh6-94w6-9r5p"
              >GHSA-qxh6-94w6-9r5p</a
            >
          </li>
        </ul>
        <h3>Supply chain</h3>
        <ul>
          <li>
            <a href="https://github.com/pnpm/pnpm/security/advisories/GHSA-379q-355j-w6rj"
              >pnpm CVE-2025-69264</a
            >
          </li>
          <li><a href="https://pnpm.io/supply-chain-security">pnpm supply-chain guidance</a></li>
          <li>
            <a
              href="https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/"
              >Datadog ChainDrop analysis</a
            >
          </li>
          <li>
            <a href="https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
              >Unit 42 ChainDrop analysis</a
            >
          </li>
        </ul>
      </details>
    </div>
  `,
  styles: `
    .wrap {
      max-width: 820px;
    }
    h1 {
      font-size: 28px;
      margin: 0 0 10px;
      line-height: 1.2;
    }
    h2 {
      font-size: 15px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      margin: 34px 0 10px;
      border-top: 1px solid var(--line);
      padding-top: 18px;
    }
    h3 {
      font-size: 16px;
      margin: 0 0 6px;
    }
    .lede {
      color: var(--muted);
      margin: 0 0 18px;
    }
    .legend p {
      margin: 6px 0;
      font-size: 14px;
      color: var(--muted);
    }
    .k {
      display: inline-block;
      min-width: 88px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      padding: 2px 8px;
      margin-right: 8px;
      border-radius: 999px;
      border: 1px solid currentColor;
      text-align: center;
    }
    .k.live {
      color: var(--live);
    }
    .k.mechanism {
      color: var(--mech);
    }
    .k.blocked {
      color: var(--blocked);
    }
    ol.chain {
      list-style: none;
      counter-reset: step;
      padding: 0;
      margin: 0;
    }
    ol.chain > li {
      counter-increment: step;
      position: relative;
      padding: 0 0 18px 42px;
      border-left: 2px solid var(--line);
      margin-left: 12px;
    }
    ol.chain > li::before {
      content: counter(step);
      position: absolute;
      left: -15px;
      top: 0;
      width: 28px;
      height: 28px;
      border-radius: 50%;
      background: var(--panel-2);
      border: 1px solid var(--line);
      color: var(--live);
      font-weight: 700;
      font-size: 13px;
      display: grid;
      place-items: center;
    }
    ol.chain p {
      margin: 0 0 6px;
      font-size: 14px;
    }
    .gate {
      color: var(--blocked);
      font-size: 13px !important;
    }
    .note {
      background: var(--panel);
      border: 1px solid var(--line);
      border-left: 3px solid var(--mech);
      border-radius: 8px;
      padding: 12px 14px;
      font-size: 14px;
    }
    .warning {
      padding: 12px 14px;
      color: #ffe0a3;
      background: #33250f;
      border: 1px solid #765820;
      border-radius: 8px;
      font-size: 14px;
    }
    ul.index {
      padding-left: 20px;
      font-size: 14px;
    }
    ul.index li {
      margin-bottom: 8px;
    }
    details.sources {
      padding: 14px 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
    }
    details.sources summary {
      cursor: pointer;
      font-weight: 700;
    }
    details.sources h3 {
      margin-top: 20px;
    }
    details.sources ul {
      columns: 2;
      padding-left: 20px;
    }
    details.sources li {
      break-inside: avoid;
      margin-bottom: 6px;
    }
    @media (max-width: 640px) {
      details.sources ul {
        columns: 1;
      }
    }
  `,
})
export class Home {
  protected readonly version = '22.1.4';
}
