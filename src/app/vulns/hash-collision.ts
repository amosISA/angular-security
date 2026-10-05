import { Component, signal } from '@angular/core';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/** The shape of hash Angular's HttpTransferCache used for cache keys. */
function djb2(input: string): number {
  let h = 5381;
  for (let i = 0; i < input.length; i++) {
    // Math.imul keeps this a real 32-bit multiply, which is the point.
    h = (Math.imul(h, 33) + input.charCodeAt(i)) | 0;
  }
  return h >>> 0;
}

interface Found {
  a: string;
  b: string;
  hash: number;
  tried: number;
  ms: number;
}

/**
 * CVE-2026-54266. The transfer cache keyed entries with a 32-bit hash.
 *
 * This page does the arithmetic in your browser rather than asking you to
 * believe it. Everything below is a real computation.
 */
@Component({
  selector: 'app-hash-collision',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="mechanism"
      heading="A 32-bit cache key is not a cache key"
      summary="Angular's SSR transfer cache hashed requests into 32 bits. Four billion buckets
               sounds enormous and is nothing. Press the button and watch."
      cve="CVE-2026-54266"
      cveUrl="https://github.com/angular/angular/security/advisories/GHSA-39pv-4j6c-2g6v"
    >
      <p>The key derivation looked like this — a DJB2-style polynomial rolling hash, truncated:</p>
      <app-code-block [code]="hashCode" label="Vulnerable 32-bit hash code" />

      <h2>Find a collision</h2>
      <p class="hint">
        This hashes plain query strings (<code>q=0</code>, <code>q=1</code>, …) and stops the moment
        two of them land in the same bucket. Because of the birthday bound you only need about
        &radic;2<sup>32</sup> &asymp; 65,000 candidates, not 4 billion — so this finishes instantly.
      </p>

      <button type="button" class="attack" (click)="search()" [disabled]="running()">
        {{ running() ? 'Searching…' : 'Search for a collision' }}
      </button>

      @if (result(); as r) {
        <pre class="loot">{{ report(r) }}</pre>
        <p>
          Two different requests, one cache key. Now reread what the transfer cache does with that
          key: it decides which cached HTTP response to hand your app on hydration.
        </p>
      }

      @if (noneFound()) {
        <pre>No collision within the search budget. Try again with a wider range.</pre>
      }

      <h2>How that became an exploit</h2>
      <p>
        The advisory's example is a query string whose hash collides with
        <code>/api/user/profile</code>. The victim opens a crafted link, SSR performs both requests,
        and the search response overwrites the profile response in the cache. The client then reads
        its "profile" and gets attacker-controlled JSON — which is privilege escalation if you trust
        the <code>role</code> field, and DOM XSS if you render it unsafely.
      </p>
      <p class="hint">
        Targeting one specific endpoint needs roughly 2<sup>32</sup> attempts rather than
        2<sup>16</sup>, which is seconds of real compute. The advisory's word is "easily".
      </p>

      <h2>The fix</h2>
      <p>
        Angular moved to SHA-256, so keys are now 256-bit hex strings and the search above stops
        being possible rather than becoming slower. Patched in 20.3.25, 21.2.17 and 22.0.1.
      </p>
      <p class="hint">
        Angular source:
        <a
          href="https://github.com/angular/angular/blob/v22.1.4/packages/common/http/src/transfer_cache.ts#L600-L625"
          target="_blank"
          rel="noopener noreferrer"
          >current SHA-256 cache-key generation</a
        >.
      </p>
      <p>If you cannot patch yet, keep sensitive endpoints out of the cache entirely:</p>
      <app-code-block [code]="fixCode" label="Transfer cache mitigation code" />
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
export class HashCollision {
  protected readonly running = signal(false);
  protected readonly result = signal<Found | null>(null);
  protected readonly noneFound = signal(false);

  protected readonly hashCode = `let h = 5381;
for (const ch of input) {
  h = (h * 33 + ch.charCodeAt(0)) | 0;   // | 0 truncates to 32 bits
}
return h >>> 0;                          // 4,294,967,296 possible keys`;

  protected readonly fixCode = `// per request
this.http.get('/api/user/profile', { transferCache: false });

// or globally
import { provideClientHydration, withNoHttpTransferCache } from '@angular/platform-browser';
providers: [provideClientHydration(withNoHttpTransferCache())];`;

  protected search() {
    this.running.set(true);
    this.result.set(null);
    this.noneFound.set(false);

    const started = performance.now();
    const seen = new Map<number, string>();
    let found: Found | null = null;

    // 400k candidates is far more than the birthday bound needs and still
    // runs in a few milliseconds.
    for (let i = 0; i < 400_000; i++) {
      const candidate = `q=${i.toString(36)}`;
      const h = djb2(candidate);
      const previous = seen.get(h);
      if (previous !== undefined) {
        found = {
          a: previous,
          b: candidate,
          hash: h,
          tried: i + 1,
          ms: Math.round((performance.now() - started) * 100) / 100,
        };
        break;
      }
      seen.set(h, candidate);
    }

    this.result.set(found);
    this.noneFound.set(found === null);
    this.running.set(false);
  }

  protected report(r: Found) {
    return [
      `request A:   /api/search?${r.a}`,
      `request B:   /api/search?${r.b}`,
      ``,
      `djb2("${r.a}") = ${r.hash}`,
      `djb2("${r.b}") = ${r.hash}`,
      ``,
      `identical cache key after ${r.tried.toLocaleString()} candidates in ${r.ms} ms`,
    ].join('\n');
  }
}
