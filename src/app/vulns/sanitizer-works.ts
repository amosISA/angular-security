import { Component, ElementRef, afterNextRender, signal, viewChild } from '@angular/core';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/**
 * The control group. Before showing bypasses it is worth watching the default
 * behaviour actually work, because the whole point is that you have to leave
 * the safe path deliberately.
 */
@Component({
  selector: 'app-sanitizer-works',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="blocked"
      heading="What Angular blocks on its own"
      summary="The default path is safe. Three payloads that all fail, and the important
               difference between escaping and sanitising."
    >
      <h2>1. Interpolation escapes</h2>
      <p class="hint">
        Nothing is ever parsed as markup here. The angle brackets become text. This is the safest
        binding in Angular and it is safe for a boring reason.
      </p>
      <div class="stage">
        <p>{{ payload }}</p>
      </div>

      <h2>2. <code>[innerHTML]</code> sanitises</h2>
      <p class="hint">
        This one <em>does</em> parse your string as HTML, then removes what it doesn't like. Inspect
        the element: the <code>onerror</code> attribute is gone.
      </p>
      <div class="stage" [innerHTML]="payload"></div>
      <pre>{{ sanitisedResult() || '(rendering…)' }}</pre>

      <h2>3. A <code>javascript:</code> URL is neutralised</h2>
      <p class="hint">
        Angular does not silently drop this — it rewrites the scheme so the browser refuses to
        navigate. Hover the link, or read the serialised attribute below.
      </p>
      <div class="stage">
        <a #jsLink [href]="jsUrl">This link goes nowhere</a>
      </div>
      <pre>{{ hrefResult() || '(rendering…)' }}</pre>

      <h2>The SVG and MathML holes, which were real</h2>
      <p>
        Three advisories in the last year were gaps in exactly this schema, all clustered in SVG and
        MathML — separate XML namespaces with their own URL-bearing attributes. On 22.1.4 these are
        all patched, so they are shown as text rather than run:
      </p>
      <app-code-block [code]="svgPayloads" language="html" label="Patched SVG payload examples" />
      <p class="sources">
        Primary advisories:
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-v4hv-rgfq-gp49"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2025-66412</a
        >,
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-jrmj-c5cx-3cw6"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2026-22610</a
        >, and
        <a
          href="https://github.com/angular/angular/security/advisories/GHSA-f3m7-gqxr-g87x"
          target="_blank"
          rel="noopener noreferrer"
          >CVE-2026-50557</a
        >.
      </p>
      <p class="hint">
        The middle one is the interesting bug. It does not bind to <code>href</code> at all — it
        binds to the <em>name of the attribute to write</em> and points that at <code>href</code>. A
        name-based security schema cannot see a URL binding there, because syntactically there isn't
        one.
      </p>
      <p class="sources">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/core/src/sanitization/dom_security_schema.ts#L18-L26"
          target="_blank"
          rel="noopener noreferrer"
          >the seven security contexts</a
        >,
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/compiler/src/schema/dom_security_schema.ts#L38-L56"
          target="_blank"
          rel="noopener noreferrer"
          >the binding security schema</a
        >, and
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/compiler/src/template_parser/template_preparser.ts#L18-L18"
          target="_blank"
          rel="noopener noreferrer"
          >the template preparser</a
        >.
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
    .sources {
      font-size: 13px;
      color: var(--muted);
    }
    .stage {
      border: 1px dashed var(--line);
      border-radius: 8px;
      padding: 14px;
      background: var(--panel);
      margin-bottom: 10px;
    }
  `,
})
export class SanitizerWorks {
  protected readonly payload = `<img hidden src=x onerror="alert('pwned')">Hello`;
  protected readonly jsUrl = 'javascript:alert(1)';

  private readonly stage = viewChild<ElementRef<HTMLElement>>('jsLink');

  protected readonly sanitisedResult = signal('');
  protected readonly hrefResult = signal('');

  protected readonly svgPayloads = `<!-- CVE-2025-66412: namespaced URL attribute missed the schema -->
<svg><a [attr.xlink:href]="untrusted"><text>click</text></a></svg>

<!-- CVE-2025-66412: attributeName retargets a safe binding at href -->
<svg><a><animate [attributeName]="'href'" [values]="untrusted" /></a></svg>

<!-- CVE-2026-22610: SVG <script> href was not a RESOURCE_URL -->
<svg><script [attr.href]="untrusted"></script></svg>

<!-- CVE-2026-50557: namespaced script survived the preparser -->
<svg:script>...</svg:script>`;

  constructor() {
    afterNextRender(() => {
      // Read back what Angular actually put in the DOM, so the claim is
      // demonstrated rather than asserted.
      const host = document.querySelector('.stage[innerHTML], app-sanitizer-works .stage');
      const sanitised = document.querySelectorAll('app-sanitizer-works .stage')[1];
      this.sanitisedResult.set(
        `rendered HTML: ${sanitised?.innerHTML.trim() ?? '(not found)'}\n` +
          `onerror survived? ${sanitised?.innerHTML.includes('onerror') ? 'YES' : 'no — stripped'}`,
      );
      void host;

      const anchor = this.stage()?.nativeElement;
      this.hrefResult.set(
        `bound value:      ${this.jsUrl}\n` +
          `serialised href:  ${anchor?.getAttribute('href') ?? '(none)'}`,
      );
    });
  }
}
