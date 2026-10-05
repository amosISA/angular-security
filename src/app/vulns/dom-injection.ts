import { Component, ElementRef, signal, viewChild } from '@angular/core';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/**
 * The other way to lose the sanitiser, and the one that does not show up when
 * you grep for `bypassSecurityTrust`.
 */
@Component({
  selector: 'app-dom-injection',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="live"
      heading="Direct DOM access skips the sanitiser entirely"
      summary="Angular's protections live in the template binding pipeline. Step outside it and
               there is nothing left to protect you — no warning, no error."
    >
      <p>
        The sanitiser is not a property of the DOM. It is a property of <em>bindings</em>. Once you
        hold a real element and assign to it yourself, you are writing plain DOM code:
      </p>
      <app-code-block [code]="vulnerableCode" label="Unsafe direct DOM injection code" />

      <h2>Attack</h2>
      <p class="hint">
        Same payload as the bypass demo, no <code>DomSanitizer</code> involved. This is why a
        <code>bypassSecurityTrust</code> grep is necessary but not sufficient.
      </p>
      <div class="row">
        <button type="button" class="attack" (click)="inject()">Assign innerHTML directly</button>
        <button type="button" (click)="clear()">Clear</button>
      </div>

      <div class="stage" #target><em>Nothing injected yet.</em></div>

      @if (fired()) {
        <pre class="loot">onerror handler fired: {{ fired() }}</pre>
      }

      <h2>The fix</h2>
      <p>
        Prefer bindings. When you genuinely need imperative DOM work, use
        <code>textContent</code> for text, or build nodes explicitly so nothing is ever parsed as
        markup:
      </p>
      <app-code-block [code]="fixedCode" label="Safe DOM text rendering code" />
      <p class="hint">
        <code>Renderer2</code> is worth knowing here too — it keeps you inside Angular's abstraction
        and works under SSR, where <code>nativeElement</code> may not be a real DOM node at all. But
        note that <code>Renderer2</code> is about portability and correctness, not sanitisation:
        <code>setProperty(el, 'innerHTML', evil)</code> is just as unsafe.
      </p>
      <p>
        Trusted Types is the control that actually closes this class off, because it makes the sink
        itself refuse a plain string.
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
      margin-bottom: 10px;
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
      margin-top: 12px;
    }
  `,
})
export class DomInjection {
  private readonly target = viewChild.required<ElementRef<HTMLDivElement>>('target');
  protected readonly fired = signal<string | null>(null);

  protected readonly vulnerableCode = `private readonly host = viewChild.required<ElementRef>('target');

render(untrusted: string) {
  // No sanitiser in this code path. There is nothing to bypass,
  // because we never entered the pipeline that would have sanitised.
  this.host().nativeElement.innerHTML = untrusted;
}`;

  protected readonly fixedCode = `// text stays text
this.host().nativeElement.textContent = untrusted;

// or build the node yourself
const el = document.createElement('span');
el.textContent = untrusted;
this.host().nativeElement.replaceChildren(el);`;

  protected inject() {
    (window as unknown as Record<string, unknown>)['__demoDomHit'] = () =>
      this.fired.set('yes — arbitrary JavaScript executed in your origin');

    this.target().nativeElement.innerHTML =
      `<img hidden src=x onerror="window.__demoDomHit()">` + `<strong>Looks harmless.</strong>`;
  }

  protected clear() {
    this.fired.set(null);
    this.target().nativeElement.textContent = 'Nothing injected yet.';
  }
}
