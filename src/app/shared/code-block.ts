import { ChangeDetectionStrategy, Component, effect, input, signal } from '@angular/core';
import type { CodeLanguage, HighlightedCode } from './shiki-highlighter';

const plainCode = (code: string): HighlightedCode => ({
  background: '#1e1e1e',
  foreground: '#d4d4d4',
  lines: code.split('\n').map((line) => [{ color: '#d4d4d4', content: line || ' ' }]),
});

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  selector: 'app-code-block',
  template: `
    <pre
      [attr.aria-label]="label()"
      [style.background-color]="highlighted().background"
      [style.color]="highlighted().foreground"
    ><code>@for (line of highlighted().lines; track $index) {<span class="line">@for (token of line; track $index) {<span [style.color]="token.color">{{ token.content }}</span>}</span>}</code></pre>
  `,
  styles: `
    :host {
      display: block;
      margin: 10px 0;
    }

    pre {
      margin: 0;
      tab-size: 2;
    }

    code,
    .line {
      font-family: var(--mono);
    }

    .line {
      display: block;
      min-height: 1.55em;
    }
  `,
})
export class CodeBlock {
  readonly code = input.required<string>();
  readonly label = input('Code example');
  readonly language = input<CodeLanguage>('typescript');

  protected readonly highlighted = signal<HighlightedCode>(plainCode(''));
  private revision = 0;

  constructor() {
    effect(() => {
      const code = this.code();
      const language = this.language();
      const revision = ++this.revision;
      this.highlighted.set(plainCode(code));

      void import('./shiki-highlighter')
        .then(({ highlightCode }) => highlightCode(code, language))
        .then((result) => {
          if (revision === this.revision) {
            this.highlighted.set(result);
          }
        })
        .catch(() => undefined);
    });
  }
}
