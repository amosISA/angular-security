import { Component, afterNextRender, signal } from '@angular/core';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/**
 * What to turn on, ordered by leverage per hour of effort rather than by
 * severity — because the ordering is what actually determines whether any of it
 * gets done.
 */
@Component({
  selector: 'app-defences',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="blocked"
      heading="What to turn on, in order"
      summary="Ordered by leverage per hour of effort. The first two are configuration, not
               engineering, and between them they would have blunted most of this page."
    >
      <h2>Live check on this page</h2>
      <p class="hint">Read from the document you are looking at right now.</p>
      <pre>{{ audit() }}</pre>

      <h2>1. minimumReleaseAge — five minutes</h2>
      <app-code-block
        [code]="cooldown"
        language="yaml"
        label="pnpm release cooldown configuration"
      />
      <p class="hint">
        A one-day delay reduces exposure to newly published malicious versions that are caught
        quickly. It cannot protect you from an older compromised release. Default in pnpm v11,
        opt-in on v10.
      </p>

      <h2>2. Strict CSP — an afternoon, report-only first</h2>
      <p>
        Angular's own advisories list "no strict CSP" and "no Trusted Types" as
        <em>preconditions for exploitability</em>. That makes CSP the control deciding whether a
        sanitiser bypass is a vulnerability or a curiosity.
      </p>
      <p>Static builds get hashes computed at build time:</p>
      <app-code-block
        [code]="autoCsp"
        language="jsonc"
        label="Angular automatic CSP configuration"
      />
      <p class="hint">
        Angular CLI source:
        <a
          href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/builders/application/schema.json#L50-L75"
          target="_blank"
          rel="noopener noreferrer"
          >security.autoCsp option</a
        >.
      </p>
      <p>Server-rendered apps need a fresh nonce per response:</p>
      <app-code-block [code]="nonce" label="Per-response CSP nonce code" />
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/application/application_tokens.ts#L110-L146"
          target="_blank"
          rel="noopener noreferrer"
          >CSP_NONCE token</a
        >.
      </p>
      <p class="hint">
        Ship it as <code>Content-Security-Policy-Report-Only</code>, collect violations for a week,
        then enforce. Going straight to enforcement is how teams conclude CSP is impractical.
      </p>

      <h2>3. Audit your bypasses — twenty minutes</h2>
      <app-code-block [code]="grep" language="bash" label="Security audit commands" />
      <p class="hint">
        Every hit is a decision a human made against a warning in the method name. Some will have
        validation beside them. The rest are your findings. Remember the second grep — the
        direct-DOM class does not show up in the first one.
      </p>

      <h2>4. Opt sensitive requests out of transfer caching — one line</h2>
      <app-code-block [code]="transfer" label="Transfer cache defence code" />
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/request.ts#L100-L140"
          target="_blank"
          rel="noopener noreferrer"
          >per-request option</a
        >
        and
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/platform-browser/src/hydration.ts#L67-L79"
          target="_blank"
          rel="noopener noreferrer"
          >global opt-out</a
        >.
      </p>

      <h2>5. Subresource Integrity and SSRF limits — one flag each</h2>
      <app-code-block
        [code]="builder"
        language="jsonc"
        label="Angular build security configuration"
      />
      <p class="hint">
        Angular CLI source:
        <a
          href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/builders/application/schema.json#L479-L483"
          target="_blank"
          rel="noopener noreferrer"
          >subresourceIntegrity</a
        >
        and
        <a
          href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/builders/application/schema.json#L231-L247"
          target="_blank"
          rel="noopener noreferrer"
          >allowedHosts</a
        >.
      </p>
      <p class="hint">
        SRI is off by default. <code>allowedHosts</code> matters the moment you server-render,
        because your server starts doing work based on a <code>Host</code> header from a stranger.
        Do not add <code>autoCsp</code> to this SSR configuration; use the per-response nonce shown
        above. The
        <a
          href="https://github.com/angular/angular-cli/blob/v22.1.6/packages/angular/build/src/utils/index-file/index-html-generator.ts#L104-L108"
          target="_blank"
          rel="noopener noreferrer"
          >Angular CLI explicitly rejects that combination</a
        >.
      </p>

      <h2>6. Trusted Types — the real fix, and the most work</h2>
      <app-code-block [code]="tt" language="http" label="Trusted Types response header" />
      <p class="hint">
        Converts DOM XSS from a runtime exploit into a runtime error. You will find every unsafe
        sink in your dependencies, which is the point and also why it takes longest.
      </p>

      <h2>Headers that are not Angular's job but are your exposure</h2>
      <app-code-block
        [code]="headers"
        language="http"
        label="Recommended security response headers"
      />
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
  `,
})
export class Defences {
  protected readonly audit = signal('(checking…)');

  protected readonly cooldown = `# pnpm-workspace.yaml
minimumReleaseAge: 1440
blockExoticSubdeps: true
trustPolicy: no-downgrade`;

  protected readonly autoCsp = `// angular.json -> projects.<app>.architect.build.options
{
  "security": {
    "autoCsp": true
  }
}`;

  protected readonly nonce = `// server.ts, per request
const nonce = randomBytes(16).toString('base64');
res.setHeader(
  'Content-Security-Policy',
  \`script-src 'nonce-\${nonce}' 'strict-dynamic'; object-src 'none'; base-uri 'none'\`,
);
providers: [{ provide: CSP_NONCE, useValue: nonce }];`;

  protected readonly grep = `rg 'bypassSecurityTrust' --type ts
rg 'nativeElement\\.(innerHTML|outerHTML)|insertAdjacentHTML' --type ts
rg 'unsafe-inline|unsafe-eval'`;

  protected readonly transfer = `this.http.get('/api/profile', { transferCache: false });
// or: provideClientHydration(withNoHttpTransferCache())`;

  protected readonly builder = `// angular.json -> projects.<app>.architect.build.options
{
  "subresourceIntegrity": true,
  "security": {
    "allowedHosts": ["example.com", "www.example.com"]
  }
}`;

  protected readonly tt = `Content-Security-Policy-Report-Only: require-trusted-types-for 'script'`;

  protected readonly headers = `Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
# clickjacking, the modern form:
Content-Security-Policy: frame-ancestors 'none'`;

  constructor() {
    afterNextRender(() => {
      const meta = document.querySelector<HTMLMetaElement>(
        'meta[http-equiv="Content-Security-Policy"]',
      );
      const state = document.getElementById('ng-state');
      const scripts = Array.from(document.querySelectorAll('script[src]'));
      const withIntegrity = scripts.filter((s) => s.hasAttribute('integrity'));

      this.audit.set(
        [
          `CSP meta tag present:      ${meta ? 'yes' : 'no  <- autoCsp is off in this build'}`,
          `Transfer cache in HTML:    ${state ? `yes (#${state.id}, ${state.textContent?.length ?? 0} bytes)` : 'no'}`,
          `Scripts with integrity:    ${withIntegrity.length}/${scripts.length}  <- subresourceIntegrity`,
          `Token readable by script:  ${localStorage.getItem('demo.auth.token') ? 'YES — sign out to clear' : 'no'}`,
        ].join('\n'),
      );
    });
  }
}
