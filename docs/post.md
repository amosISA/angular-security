---
title: 'Angular sanitises by default. Here is where that sentence runs out.'
description: "A vulnerability-by-vulnerability tour of Angular security in 2026 — sanitiser bypasses, SSR transfer cache poisoning, i18n XSS, strict CSP, and the npm worm that made your lockfile the attack surface. Checked against Angular 22.1.4."
date: 2026-08-31
tags: [angular, security, xss, csp, supply-chain, ssr, angular22]
angularVersion: '22.1.4'
---

# Angular sanitises by default. Here is where that sentence runs out.

I set out to write the Angular security checklist. Ten headings, a code snippet each, a reassuring paragraph about how the framework has your back, ship it before lunch.

Then I went and read every Angular security advisory published in the last twelve months, and the checklist fell apart. Not because Angular's protections are weak. Because **almost every real Angular vulnerability of the past year happened in a place the phrase "Angular escapes untrusted values" does not reach.**

That's the honest shape of this topic, so that's the shape of this post. I'm going to go vulnerability by vulnerability. For each one I want to be specific about three things: what the mechanism actually is, what has to be true in your app for it to bite you, and what you do about it. Every version number and API name below was checked against the installed type definitions of `@angular/core@22.1.4`, `@angular/common@22.1.4`, `@angular/platform-browser@22.1.4` and `@angular/build@22.1.4`, or against the primary advisory. Where I'm reading someone else's incident report rather than code, I'll say so.

Let's start with the thing that works, because you can't see the gaps until you know the shape of the wall.

---

## Part one: what the sanitiser actually is

Angular's XSS defence is a small idea applied relentlessly. Every place a value can flow into the DOM from a template is assigned a **security context**, and the value gets treated according to that context rather than according to what you meant.

There are exactly seven contexts. I counted them in `core/types/_debug_node-chunk.d.ts`:

```ts
enum SecurityContext {
  NONE = 0,
  HTML = 1,
  STYLE = 2,
  SCRIPT = 3,
  URL = 4,
  RESOURCE_URL = 5,
  ATTRIBUTE_NO_BINDING = 6,
}
```

That enum is the entire security model in seven lines. The compiler decides which context a given binding lands in, and the runtime applies the matching treatment.

Worth separating two things people merge:

```html
<!-- escaped: the value becomes text, no HTML is parsed at all -->
<p>{{ userBio }}</p>

<!-- sanitised: the value IS parsed as HTML, then dangerous parts are removed -->
<p [innerHTML]="userBio"></p>
```

Interpolation is the safe one and it's safe for a boring reason: nothing is ever parsed as markup. `[innerHTML]` genuinely parses your string and then strips what it doesn't like. Both are fine. But only one of them is fine *because the parser never ran*, and that difference is going to matter in about four sections' time.

`RESOURCE_URL` is the strict one. A URL that the browser will load and execute code from — an `<iframe src>`, a `<script src>` — cannot be sanitised, because there is no meaningful way to make an arbitrary script URL safe. So Angular refuses it outright and makes you say so explicitly.

Which brings us to the front door.

---

## Part two: the bypass you open yourself

`DomSanitizer` is an abstract class in `@angular/platform-browser`, and it exposes five methods whose names should read as warnings:

```ts
bypassSecurityTrustHtml();
bypassSecurityTrustStyle();
bypassSecurityTrustScript();
bypassSecurityTrustUrl();
bypassSecurityTrustResourceUrl();
```

Every one of them is a promise you're making to the framework. You are asserting that you have already established this value is safe, and Angular believes you, because it has no way not to.

The version I find most often, in a component that embeds a video:

```ts
// please don't
readonly embedUrl = computed(() =>
  this.sanitizer.bypassSecurityTrustResourceUrl(this.videoUrl()),
);
```

If `videoUrl()` came from an API, a CMS, or a route parameter, that line is a stored XSS vulnerability wearing a helpful-utility costume. `bypassSecurityTrustResourceUrl` on attacker-controlled input is equivalent to putting their URL in a `<script src>`, because in the `<iframe>` case it very nearly is.

The fix is not a cleverer sanitiser call. It's an allowlist, and it belongs before the value ever reaches the template:

```ts
const ALLOWED = ['www.youtube-nocookie.com', 'player.vimeo.com'];

readonly embedUrl = computed(() => {
  const url = new URL(this.videoUrl());          // throws on nonsense
  if (url.protocol !== 'https:') return null;
  if (!ALLOWED.includes(url.hostname)) return null;
  return this.sanitizer.bypassSecurityTrustResourceUrl(url.href);
});
```

`new URL()` is doing real work there. It normalises, and it throws on malformed input, which means you're validating a parsed URL rather than pattern-matching a string. String matching on URLs is how you end up trusting `https://www.youtube-nocookie.com.evil.tld`.

**Every `bypassSecurityTrust*` call in your codebase should have a validation step you can point at.** If you can't point at one, you have found a bug. That's a grep you can run this afternoon, and it's the highest-value fifteen minutes in this entire post.

Now the part where the wall itself had holes.

---

## Part three: four sanitiser bypasses, in the sanitiser

Here's what surprised me. I expected the year's advisories to be mostly developer error. They weren't. Three advisories, four distinct bypasses, and every one of them is the framework's own security schema being incomplete — clustered in one specific corner: **SVG and MathML.**

The reason they cluster there is structural. Angular's compiler holds a schema mapping element and attribute names to security contexts. HTML is well covered because HTML is what everyone tests. SVG and MathML are separate XML namespaces bolted into the HTML parser, they have their own URL-bearing attributes, and each one is a chance for the schema to have a gap.

### The attribute-name gap

[CVE-2025-66412](https://github.com/advisories/GHSA-v4hv-rgfq-gp49) is the schema failing to mark certain namespaced URL attributes as URL-security contexts. `xlink:href`, `math|href`, `annotation|href`. Bind untrusted data to one of those and the compiler falls back to a non-sanitising context:

```html
<!-- pre-patch: the sanitiser is simply not consulted here -->
<svg><a [attr.xlink:href]="untrusted"><text>click</text></a></svg>
```

A `javascript:` URL in `untrusted` executes on click. Patched in 19.2.17, 20.3.15 and 21.0.2.

The same advisory covers something nastier. SVG animation elements — `<animate>`, `<set>`, `<animateMotion>`, `<animateTransform>` — take an `attributeName` attribute that says *which attribute to animate*. That wasn't validated. So you get indirection:

```html
<!-- pre-patch: attributeName was not validated, so this retargets href -->
<svg>
  <a><animate [attributeName]="'href'" [values]="untrusted" /></a>
</svg>
```

You are not binding to `href`. You are binding to the *name of the attribute to write*, and pointing it at `href`. The sanitiser never sees a URL binding because syntactically there isn't one. And per the advisory this can fire on animation rather than needing a click.

I like this bug because it shows the limit of the whole approach. **A name-based security schema can only protect attributes it knows are dangerous, and SVG has an attribute whose entire job is to name another attribute.**

### The SVG `<script>` gap

[CVE-2026-22610](https://github.com/advisories/GHSA-jrmj-c5cx-3cw6) is narrower and easier to explain. SVG has its own `<script>` element, and its `href`/`xlink:href` weren't classified as `RESOURCE_URL`:

```html
<!-- pre-patch: treated as an ordinary string, not a resource URL -->
<svg><script [attr.href]="untrusted"></script></svg>
```

A `data:text/javascript` payload runs. In HTML, `<script src>` is one of the most carefully guarded bindings in the framework. In SVG, the same idea went through a different code path with a different name and got a different answer. Patched in 19.2.18, 20.3.16, 21.0.7 and 21.1.0-rc.0.

### The namespace gap

[CVE-2026-50557](https://github.com/advisories/GHSA-f3m7-gqxr-g87x) is the most interesting of the three and the least likely to affect you.

Angular's template preparser strips `<script>` elements. It did not recognise these as script elements:

```html
<svg:script>...</svg:script>
<:svg:script>...</:svg:script>
```

Namespace-prefixed, so the tag-name check missed them, so they survived compilation. Combined with gaps in attribute security contexts inside namespaced elements, you get a full sanitiser bypass. Patched in 19.2.23, 20.3.22, 21.2.15 and 22.0.0-rc.2.

Read the precondition carefully, though, because it's the whole story: **the application must compile user-controlled templates at runtime.** Not render user data through a template. *Compile a template that came from a user.* If you don't do that — and almost nobody should — this one cannot touch you.

Which is the useful takeaway sitting underneath all three. Angular's sanitiser is a blocklist of known-dangerous names wearing an allowlist's clothing. It has been very good for a decade. It is not a boundary you should rely on alone, and the framework's own docs agree: the advisory for the i18n bug we're about to hit lists "no strict CSP" and "no Trusted Types" as *preconditions for exploitability*.

Hold that thought.

---

## Part four: XSS where the sanitiser was never invited

Now we leave the sanitiser behind entirely, and this is where the year gets genuinely novel.

### Your translation files are executable

[CVE-2026-27970](https://github.com/advisories/GHSA-prjf-86w9-mfqv). ICU messages in Angular's i18n pipeline weren't sanitised, so HTML in translated content could execute.

The mechanism is not the interesting part. The supply chain is. Think about how translations actually get made:

You extract messages from your app. You send an `.xlf` file to a translation vendor. Some number of contractors you have never met edit that file. It comes back. Your build merges it into your compiled application, at build time, as trusted source.

**Your translation file has the same privileges as your source code and roughly none of the review.** Nobody diffs an incoming `.xlf` the way they'd diff a pull request. It's 4,000 lines of strings in a language most of the team doesn't read.

Note the attack precondition, which is unusual and worth being precise about: this is not exploitable by an arbitrary user of your app. The attacker has to compromise the translation file first. That makes it a lower-probability, higher-blast-radius bug — it lands in your build output, signed and shipped, for every user in that locale.

Patched in 19.2.19, 20.3.17, 21.1.6 and 21.2.0. But the structural lesson outlives the patch: treat translation files as untrusted input with a build-time review step, because that is exactly what they are.

### The server-side DOM lied about escaping

[CVE-2026-69149](https://github.com/advisories/GHSA-vpx6-8pjr-4g3v) is my favourite of the year, because it's a bug about *disagreement between two parsers*.

Angular SSR doesn't have a browser. It uses `domino`, a DOM emulation library, to build and serialise the page. Domino's serialiser did not escape text nodes inside what the spec calls fallback raw-content elements: `<iframe>`, `<noembed>`, `<noframes>`, `<noscript>`.

So:

```html
<!-- SSR, pre-patch -->
<noscript>{{ userComment }}</noscript>
```

Under a real browser, that's inert — the content is raw text. Under domino's serialiser, a closing tag inside `userComment` was written out literally, closing the element early and letting whatever follows be parsed as markup.

The detail that makes it real: the trigger is **critical CSS inlining**, an unrelated performance feature that re-parses and re-serialises your rendered HTML through domino. A build optimisation is what turns the serialisation flaw into shipped XSS.

Patched in 20.3.27, 21.2.19 and 22.0.7. If you're pinned below those, the mitigation is to turn off the re-parse:

```jsonc
// angular.json — @angular/build:application
"optimization": {
  "styles": { "inlineCritical": false }
}
```

I checked that option exists in the installed builder schema. It does, under `optimization.styles`.

**Two parsers that disagree about what "raw text" means is an escaping bug waiting to be discovered, and SSR gives you two parsers by definition.**

---

## Part five: SSR built you a new attack surface

If you take one section from this post, take this one. Three separate advisories, all in the same feature, all from this year, and I'd bet most Angular developers running SSR don't know the feature exists.

Here's what it is. When you enable hydration, Angular avoids re-fetching data on the client by caching the HTTP responses it made during SSR and shipping them to the browser inside the HTML:

```html
<script type="application/json" id="ng-state">
  { "some-api-url": { "body": ... } }
</script>
```

That's the `HttpTransferCache`, and it's on by default with `provideClientHydration()`. It is a serialised copy of your server's HTTP responses, embedded in a public document, keyed by request. Three things went wrong with it.

### 1. It cached authenticated responses

[CVE-2026-50170](https://github.com/advisories/GHSA-q6f4-qqrg-jv6x). The cache didn't inspect `withCredentials` or the `Cookie` header. So a per-user authenticated response got serialised into the HTML.

On its own, that's just redundant. Combined with any shared cache in front of your app — a CDN, a reverse proxy, Cloudflare, Varnish, whatever your infra team set up last year — one user's private data is in an HTML document that gets served to the next visitor.

That's the shape I want you to notice: **the framework bug is a leak, and your CDN is what turns it into a breach.** Neither team owns the whole vulnerability. Patched in 19.2.23, 20.3.22, 21.2.15 and 22.0.0-rc.2.

### 2. The cache keys were 32 bits

[CVE-2026-54266](https://github.com/advisories/GHSA-39pv-4j6c-2g6v), and this one is beautiful.

Cache keys were generated with a DJB2-style 32-bit rolling hash. Four billion possible keys, which sounds like a lot and is nothing — you can brute-force a collision on a laptop in seconds.

From the advisory, concretely: an attacker finds a search query whose hash collides with `/api/user/profile`. They send the victim a crafted link. SSR performs both requests. The search response overwrites the profile response in the cache. Your client then reads its "profile" from the transfer cache and gets attacker-controlled JSON.

That's state poisoning, and depending on what you render, it's DOM XSS or privilege escalation. The fix moved cache keys to SHA-256. Patched in 20.3.25, 21.2.17 and 22.0.1.

One detail I can't resist: per the advisory, this was found by **CodeMender, from Google DeepMind.** An AI agent found the hash-collision bug in Google's own framework. I don't have a tidy conclusion about that; I just think you should know it happened.

### 3. `ng-state` was a guessable ID

[CVE-2026-54267](https://github.com/advisories/ghsa-rgjc-h3x7-9mwg), which chains DOM Clobbering into the same cache.

Angular recovers that state with `document.getElementById('ng-state')`. DOM Clobbering is the old trick where a named element wins a `getElementById` lookup. So if your app binds untrusted input to an element `id`, and that element is parsed before the real script tag:

```html
<!-- vulnerable: attacker supplies the id -->
<div [id]="userControlledInput">...</div>
```

The attacker's element wins the lookup. Angular parses *their* content as the state JSON. They map a key for `/api/user/profile` to whatever they like, and `HttpClient` — which checks the transfer cache before making a request — serves the forged response instead of calling your backend. No network request is made, so nothing on the server side ever sees the attack.

Why `ng-state`? Because `APP_ID` defaults to `'ng'`. I went and looked: `APP_ID` is an `InjectionToken<string>` in `core/types/core.d.ts`, and the docs comment confirms `ng` is the fallback. The state element ID is derived from it, which is why it's predictable in literally every default Angular app.

Patched in 20.3.25, 21.2.17 and 22.0.1. The advisory's workarounds are worth knowing even patched — prefix any dynamic ID, and set a non-guessable `APP_ID`:

```ts
providers: [
  { provide: APP_ID, useValue: 'k7d92m-app' },  // lookup becomes k7d92m-app-state
  provideClientHydration(),
]
```

### What to actually do about the transfer cache

Patch, obviously. But there's a design decision underneath these three bugs that's yours, not Angular's: **the transfer cache is a performance feature that publishes your server's HTTP responses, and it defaults to on.**

For anything user-specific, opt out. Per request:

```ts
this.http.get('/api/user/profile', { transferCache: false });
```

Or globally, if you'd rather pay the refetch and stop thinking about it:

```ts
import { provideClientHydration, withNoHttpTransferCache } from '@angular/platform-browser';

providers: [provideClientHydration(withNoHttpTransferCache())];
```

I verified both: `transferCache?: { includeHeaders?: string[] } | boolean` on the request options in `common/types/http.d.ts`, and `withNoHttpTransferCache` exported from `platform-browser`.

Three CVEs in one feature in one year is not bad luck. It's what a young feature looks like when it sits on the boundary between two trust domains.

---

## Part six: the defence that would have caught most of the above

Go back and re-read the i18n advisory's preconditions. "The victim application must not defend against XSS via a safe Content-Security-Policy or Trusted Types."

The framework's own security advisory is telling you that CSP is not defence in depth here. **It is the control that decides whether a sanitiser bypass is a vulnerability or a curiosity.** Most of Part three and Part four dies against a strict CSP, because a `javascript:` URL and an injected inline script both need permission to execute, and a strict CSP doesn't grant it.

So why doesn't everyone run one? Because Angular injects inline styles at runtime, a naive strict CSP breaks your app's appearance immediately, and the fastest way to make the error go away is `unsafe-inline`. At which point you have a CSP header and no CSP.

Angular has two supported answers, and which one you want depends entirely on whether you server-render.

### Static builds: hash-based, via `autoCsp`

For client-side rendering, the builder can compute SHA-256 hashes of your inline scripts at build time. It's a single flag, nested under a `security` key in your build options:

```jsonc
// angular.json → projects.<app>.architect.build.options
{
  "security": {
    "autoCsp": true
  }
}
```

Two things I found in the schema worth repeating. The default is `false`, and the description says it "will default to true once we are out of experimental/preview phases" — so this is on Angular's roadmap to become the default, and turning it on now is moving early rather than doing something exotic.

The other thing is the escape hatch:

```jsonc
"security": { "autoCsp": { "unsafeEval": true } }   // think hard first
```

The schema's own description asks you to only enable this if you're absolutely certain, because it weakens the XSS defence the feature exists to provide. If a dependency needs `unsafe-eval`, the interesting question is why you're still shipping that dependency.

### SSR: nonce-based, via `CSP_NONCE`

Hashes don't work when the server generates markup per request, so you use a nonce: a fresh random value per response, in both the CSP header and the tags allowed to run.

Angular exposes `CSP_NONCE`, which I confirmed is an `InjectionToken<string | null>` in `core/types/core.d.ts`. You generate a nonce per request and provide it during bootstrap:

```ts
// server.ts — per request
const nonce = randomBytes(16).toString('base64');

res.setHeader(
  'Content-Security-Policy',
  `script-src 'nonce-${nonce}' 'strict-dynamic'; style-src 'nonce-${nonce}'; object-src 'none'; base-uri 'none'`,
);

// pass it into the render so Angular tags its injected styles with it
providers: [{ provide: CSP_NONCE, useValue: nonce }];
```

The part that catches people: **the nonce must be regenerated per response, and it must be unguessable.** A nonce baked into a build artefact, or derived from anything an attacker can predict, is decorative. If you're caching SSR output at a CDN, you now have the nonce and the cache interacting, and that needs thinking about rather than hoping.

`'strict-dynamic'` is worth the search if it's new to you — it lets a trusted script load further scripts, which is what makes strict CSP survive contact with real applications instead of dying on the first dynamic import.

### Trusted Types

CSP stops injected scripts from running. Trusted Types goes further up the pipe: it makes the *dangerous DOM sinks themselves* refuse plain strings. `innerHTML`, `eval`, `script.src` — with Trusted Types enforced, assigning a raw string to any of them throws.

That converts DOM XSS from a runtime exploit into a runtime error, which is a much better place for it to be. The Angular advisory for the i18n bug links the Trusted Types API directly, which tells you the framework team considers it a real control and not a curiosity.

It's the highest-effort item in this post, because you'll find every sink in your dependencies whether you wanted to or not. Start in report-only mode, in both cases:

```
Content-Security-Policy-Report-Only: require-trusted-types-for 'script'
```

Report-only first is the general rule for all of this. Ship the header, collect violations for a week, then enforce. Going straight to enforcement on a real app is how you end up rolling back at 6pm and telling your team CSP isn't practical.

---

## Part seven: the attack that ignores your framework completely

Everything so far has been Angular's problem in some sense. This one isn't, and it's the one that actually took people down this month.

On 4 August 2026, a self-propagating npm worm — Unit 42 named it **ChainDrop**, and it's part of the Shai-Hulud code lineage — compromised over 400 packages. Some of them have north of 150 million weekly downloads. `keyv`, `cacheable-request`, `cache-manager`, `flat-cache`, `file-entry-cache`, the `@cacheable/*` scope.

Everything below comes from the [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/) and [Unit 42](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) analyses. I'm reading their work, not malware.

Here is the entire change to the package manifest:

```json
{
  "scripts": {
    "preinstall": "node setup.mjs"
  }
}
```

That's it. The package's real code is untouched and still works. Your tests pass. Nothing looks wrong.

`setup.mjs` is an 11 KB dropper. It looks for Bun on your PATH, and if it isn't there, downloads Bun 1.3.13 from the genuine `oven-sh/bun` GitHub releases — Datadog notes it does not cryptographically verify the download — then runs a 727 KB obfuscated payload under Bun rather than Node.

Bun is not compromised. It's being used as a portable execution vehicle, partly because monitoring tuned to Node's runtime internals doesn't see it.

Then it reads your machine. Cloud credentials, npm and GitHub tokens, SSH keys, `.env`, `.netrc`, shell history, Docker, Terraform, Vault, Kubernetes service account tokens, crypto wallets, credentials for AI coding tools. Datadog counted the file patterns: 290 for Linux, 129 for macOS, 50 for Windows.

Three details that reframe what "dependency risk" means:

**It reads CI runner memory.** On GitHub Actions, it pipes an embedded Python program into `sudo python3`, finds the `Runner.Worker` process, and reads `/proc/<pid>/mem` looking for secrets. Secrets that were never written to disk, that expire when the job ends, are readable while the job runs.

**It persists through your editor and your AI tooling.** It writes `.vscode/tasks.json` with a task that runs on folder open, and `.claude/settings.json` with a `SessionStart` hook. Cross-linked, so each one launches the dropper copy sitting in the other tool's directory. Opening the project re-infects you. These are not files anyone audits.

**Its command-and-control address lives in an Ethereum smart contract.** No hardcoded domain. The payload calls a contract to ask where to send your data. On 4 August the operator rotated the C2 domain with a single on-chain transaction — no malware update needed, and the contract emits no events, so the rotation is silent. Block today's domain and you've bought a day.

### The bit that should genuinely change your habits

Two findings from those reports matter more than the malware.

**First: the worm published a package with valid npm provenance.** One code path uses GitHub's OIDC trusted-publishing exchange to mint a real publish credential, builds a genuine in-toto SLSA attestation, signs it with Sigstore, and uploads to the public Rekor transparency log.

Unit 42's phrasing is the part to internalise: this is not forged provenance. The attestation truthfully says the tarball was built by that workflow in that repository. It was. **If the workflow is running attacker code, valid provenance is exactly what you should expect to see.** Provenance tells you where a package came from. It does not tell you the package is clean, and a lot of teams have quietly started treating those as the same claim.

**Second: rolling back the `latest` tag does not fix you.** Unit 42 found a "remediated" system where the tag had been repointed at a clean version and nothing else had changed. Your lockfile still pins the compromised version. So do your CI image layers, your package caches, and your internal mirror. Fixing the registry does not reach into artefacts that already exist on your infrastructure.

So the remediation is: clear caches, rebuild images, regenerate the lockfile entry, *then* verify. And rotate every credential the affected machine could reach, because the entire point of the payload was to collect them.

---

## Part eight: does pnpm actually help? Yes, with caveats

This is where the topic usually turns tribal, so let me be specific instead.

**pnpm's advantage is real and specific.** As of pnpm v10, dependency lifecycle scripts do not run on install. You allowlist the ones that genuinely need to build:

```yaml
# pnpm-workspace.yaml
onlyBuiltDependencies:
  - esbuild
```

A naming warning, because I got this wrong while writing and only caught it by testing: the current pnpm documentation recommends `allowBuilds`, but that name landed in v11. On v10 it is `onlyBuiltDependencies`, and `allowBuilds` is silently ignored. I confirmed it on pnpm 10.28.0 — `pnpm config get allowBuilds --json` returns nothing while `onlyBuiltDependencies` returns the array. If you're reading the docs site and running v10, you can write a setting that does nothing and never hear about it. There's also a `dangerouslyAllowAllBuilds` escape hatch, named with admirable honesty.

That default removes exactly the vector ChainDrop used. A `preinstall` hook in a compromised transitive dependency does not execute. Not mitigated, not sandboxed — not run.

**And it is not a silver bullet.** [CVE-2025-69264](https://github.com/pnpm/pnpm/security/advisories/GHSA-379q-355j-w6rj) is the bypass: pnpm v10 blocked `postinstall` through that allowlist, but git-hosted dependencies took a different code path and could still run `prepare`, `prepublish` and `prepack` during fetch. Remote code execution, no approval. Fixed in pnpm 10.26.

That CVE also points at a setting worth having regardless:

```yaml
blockExoticSubdeps: true
```

That stops transitive dependencies resolving from git repositories or direct tarball URLs. A direct dependency on a git URL is a decision you made. A *transitive* one is a decision someone else made on your behalf, and it's the code path that produced the CVE above. Unlike `allowBuilds`, this one does resolve on v10 — I checked it on 10.28.0.

I think that CVE makes the case for pnpm rather than against it, but only if you draw the right conclusion. The lesson isn't "pnpm is safe". It's that **"do not execute arbitrary code on install" is a security boundary, and boundaries have to be complete to be boundaries.** pnpm drew one, missed a path, and closed it. npm hasn't drawn one at all by default.

If you're on npm, you can get most of the way there yourself:

```ini
# .npmrc
ignore-scripts=true
```

Then run the handful of builds you actually need explicitly. It's the same idea with worse ergonomics and no allowlist, which is why I'd rather change package manager than maintain that by hand.

### The cheapest mitigation on this entire page

Malicious versions are usually caught and yanked within hours. So don't install anything that new.

```yaml
# pnpm-workspace.yaml
minimumReleaseAge: 1440 # minutes — one day
```

In pnpm v11 this defaults to 1440. On v10 it's opt-in, and it is the single highest-leverage line of configuration in this post. It costs you a one-day delay on updates you were not going to read the diff of anyway, and it would have protected you from ChainDrop, from the axios incident, and from most of the smash-and-grab campaigns of the last year. Set it to `10080` if you want a week; set it to `0` to opt out on v11.

### Two more settings, and one lockfile trap

While I was checking the above I found a setting that speaks directly to the provenance problem from Part seven:

```yaml
trustPolicy: no-downgrade
```

That refuses to install a package whose *trust level has decreased* relative to earlier releases — for example, a package that used to ship from a trusted publisher and now arrives with only provenance, or with nothing. It doesn't try to answer "is this package clean", which we established is unanswerable from an attestation. It answers a question that's actually tractable: **did the publishing story for this package just get worse?** That's a much better question, and a change in trust posture is exactly what a compromised release looks like from the outside. Also resolves on 10.28.0.

For dependency confusion — the attack where a public package impersonates your internal scope — pnpm records registry-qualified lockfile keys when you alias packages through `namedRegistries` (v11.20.0+), so a package can't be quietly substituted by a different registry publishing the same name and version. If you install from more than one registry, that's worth reading up on.

And one trap I'd never have guessed, straight from pnpm's own docs: `pnpm-lock.yaml` is a **two-document YAML file**, and a scanner that reads only the first document will report that your project has no dependencies and no vulnerabilities — and will not fail while doing it. A green SBOM or vulnerability scan is not evidence until you've confirmed your tooling actually parsed the whole lockfile. Go and check that your scanner reports a plausible dependency count.

For reference on what I tested against: pnpm 10.28.0 locally, 11.24.0 latest published, npm 10.8.2.

**Your lockfile is a list of programs you have agreed to run on every machine that builds your app, including your CI runner with its cloud credentials.** Treat it accordingly.

---

## Part nine: the part Angular tells you isn't its job

Angular's security documentation says up front that it doesn't cover authentication and authorisation. People read that as "handled elsewhere" rather than "handled by you", and here's where that goes wrong.

### Route guards are not a security boundary

```ts
// this is UX, not security
export const adminGuard: CanActivateFn = () => inject(Auth).isAdmin();
```

That runs in the browser. The user has your bundle. They can read the guard, and they can call your API without ever loading your app. A guard decides which view a cooperative user sees. **Every authorisation decision that matters happens on the server, and the guard is a convenience that keeps honest users out of broken screens.**

The same goes for anything you decode from a JWT client-side. Reading `role: 'admin'` out of a token to decide what to render is fine. Reading it to decide what's *allowed* is not, because the client half of that conversation is attacker-controlled.

### Token storage, and why this is really an XSS question

Implicit flow is dead for SPAs; use Authorization Code with PKCE. That part is settled and well documented.

The unsettled part is where the token goes, and I want to connect it to Part three rather than treat it as a separate topic. `localStorage` is readable by any JavaScript running on your origin. So the entire question "is `localStorage` safe for tokens" reduces to "am I certain I have no XSS" — and the four sanitiser bypasses above are the reason nobody gets to be certain.

Which is why the answer is to stop holding the credential in JavaScript at all. A backend-for-frontend keeps tokens server-side and gives the browser a `HttpOnly`, `Secure`, `SameSite` cookie. XSS can then *make requests* as the user, which is bad, but it cannot *steal a token* and keep using it from somewhere else, which is much worse.

**A stolen token outlives the XSS. A session cookie the script can't read does not.** That's the whole argument, and it's why every "just use localStorage, it's fine" thread misses the point.

### XSRF: Angular does half, and the half it does is precise

`HttpClient` reads the `XSRF-TOKEN` cookie and echoes it as the `X-XSRF-TOKEN` header. Configurable:

```ts
provideHttpClient(
  withXsrfConfiguration({
    cookieName: 'XSRF-TOKEN',
    headerName: 'X-XSRF-TOKEN',
  }),
);
```

I verified `withXsrfConfiguration`, `withNoXsrfProtection` and `HttpXsrfTokenExtractor` are all exported from `@angular/common/http` in 22.1.4.

Three constraints on that behaviour that are easy to get wrong. It only applies to mutating methods, so `GET` and `HEAD` don't carry the token. It only applies to relative URLs — Angular deliberately will not send your token to an absolute cross-origin URL, which is correct and occasionally confusing when your API is on another domain. And **the server has to issue the cookie and validate the header.** Angular's half is worthless alone. Adding the provider and moving on is a real and common mistake.

---

## Part ten: the unglamorous ones that still get you

Short section, real bugs.

**Source maps.** Check what you're actually deploying. `ls dist/**/*.map` is a one-line audit, and it catches more production deployments than it has any right to.

**`environment.ts` is public.** It compiles into the bundle. Any API key in there is published. There's no such thing as a frontend secret — if the browser can use it, the user has it. Public identifiers are fine; anything you'd be upset to see in a paste bin belongs on a server.

**Subresource Integrity is one flag and it's off.** I checked the builder schema: `subresourceIntegrity`, boolean, `default: false`.

```jsonc
// angular.json → projects.<app>.architect.build.options
{ "subresourceIntegrity": true }
```

That makes the browser verify a hash before executing your scripts. Given Part seven was about compromised distribution, turning this on is cheap and obviously correct.

**SSRF in SSR, which is new to a lot of people.** The builder has a `security.allowedHosts` array, and its schema description links straight to Angular's page on preventing server-side request forgery. Once you server-render, your server takes a `Host` header from a stranger and does work with it. Constrain it:

```jsonc
// angular.json → projects.<app>.architect.build.options
{
  "security": {
    "allowedHosts": ["example.com", "www.example.com"],
    "autoCsp": true
  }
}
```

**Security headers.** Not Angular's job, still your app's exposure. `Strict-Transport-Security`. `X-Content-Type-Options: nosniff`. `frame-ancestors 'none'` in your CSP for clickjacking, which is the modern replacement for `X-Frame-Options`. `Referrer-Policy`. `Permissions-Policy` to turn off browser APIs you don't use. These live in your reverse proxy or CDN config and take an afternoon once.

---

## The pattern I'd look for first

<!--
NOTE FOR YOU BEFORE PUBLISHING:
Your other two posts both have a section where you show a bug you actually
wrote ("The bug I wrote" in the signals post, "I had it wrong myself, in
writing, and I'll show you the receipts" in the timezones one). That first-person
admission is the most distinctive thing in your voice and readers trust it.

I can't invent that memory for you. Replace this section with a real one:
a bypassSecurityTrust* call you shipped, a transfer cache leak you found,
an environment.ts key that got published, a CSP you disabled to make a
build pass. Anything real. If you'd rather not, delete the section entirely
and keep the aphorism at the end — the post works without it.
-->

If I had one hour on an unfamiliar Angular codebase, I'd spend it on this grep:

```bash
rg 'bypassSecurityTrust' --type ts
```

Not because it's the most severe issue on this page, but because it's the one where the framework has already flagged the danger in the method name and a human overrode it anyway. Every hit is a decision someone made. Some will have validation next to them. The rest are your findings.

Second hour: `rg 'unsafe-inline|unsafe-eval'`, then check whether `provideClientHydration()` is caching anything user-specific.

---

## The table

| Vulnerability | What it actually is | Patched in |
| --- | --- | --- |
| [CVE-2025-66412](https://github.com/advisories/GHSA-v4hv-rgfq-gp49) | SVG/MathML URL attrs missing from security schema; SVG `attributeName` unvalidated | 19.2.17, 20.3.15, 21.0.2 |
| [CVE-2026-22610](https://github.com/advisories/GHSA-jrmj-c5cx-3cw6) | SVG `<script href>` not treated as `RESOURCE_URL` | 19.2.18, 20.3.16, 21.0.7 |
| [CVE-2026-50557](https://github.com/advisories/GHSA-f3m7-gqxr-g87x) | `<svg:script>` survives preparser; needs runtime template compilation | 19.2.23, 20.3.22, 21.2.15, 22.0.0-rc.2 |
| [CVE-2026-27970](https://github.com/advisories/GHSA-prjf-86w9-mfqv) | ICU translation content not sanitised | 19.2.19, 20.3.17, 21.1.6, 21.2.0 |
| [CVE-2026-69149](https://github.com/advisories/GHSA-vpx6-8pjr-4g3v) | domino doesn't escape raw-content elements; triggered by critical CSS inlining | 20.3.27, 21.2.19, 22.0.7 |
| [CVE-2026-50170](https://github.com/advisories/GHSA-q6f4-qqrg-jv6x) | Transfer cache stores credentialed responses; leaks via shared cache | 19.2.23, 20.3.22, 21.2.15, 22.0.0-rc.2 |
| [CVE-2026-54266](https://github.com/advisories/GHSA-39pv-4j6c-2g6v) | 32-bit cache keys; trivial collisions poison state | 20.3.25, 21.2.17, 22.0.1 |
| [CVE-2026-54267](https://github.com/advisories/ghsa-rgjc-h3x7-9mwg) | DOM Clobbering of `ng-state` poisons transfer cache | 20.3.25, 21.2.17, 22.0.1 |
| [CVE-2025-69264](https://github.com/pnpm/pnpm/security/advisories/GHSA-379q-355j-w6rj) | pnpm: git deps ran `prepare` despite script blocking | pnpm 10.26 |

If you're on a supported line, the floor is 19.2.25, 20.3.30, 21.2.22 or 22.1.4 as I write this. Everything in that table is already fixed above those.

---

## Where the framework stops

Angular's security model is genuinely good, and I want to be fair to it before I finish. Treating every value as untrusted by default, assigning security contexts at compile time, refusing resource URLs outright, making the bypass functions ugly enough to notice in review — that design has prevented an enormous number of bugs that were routine in the jQuery era. Google's secure-by-design argument is basically correct: the framework should make the safe path the default path, and Angular mostly does.

But look at where this year's bugs actually landed, because the pattern is not random.

They landed at the **edges of the schema**, in namespaces the sanitiser's name-based blocklist didn't fully cover. They landed at **boundaries between trust domains** — a translation vendor's file, a CDN's cache, a server-rendered payload handed to a client. They landed in **young features that cross those boundaries**, which is why the transfer cache produced three on its own. And the worst one of the month didn't involve Angular at all; it came through a `preinstall` script in a cache library four levels down your dependency tree.

None of those are places a sanitiser can reach. Which is the actual conclusion, and it's less comfortable than a checklist: **the framework can make the default safe, but it cannot make the boundary safe, because the boundary is where your infrastructure and your suppliers and your build pipeline meet — and Angular can't see any of those.**

So patch, obviously. Then do the three things nobody does: turn on `autoCsp` and get to a strict CSP in report-only mode this week, set `minimumReleaseAge` before you close the tab, and go read every `bypassSecurityTrust*` call in your repo.

The last one takes twenty minutes and you will find something.

---

_Every Angular API name, version number and configuration key above was checked against the installed type definitions and builder schemas of `@angular/core@22.1.4`, `@angular/common@22.1.4`, `@angular/platform-browser@22.1.4` and `@angular/build@22.1.4`, or against the linked GitHub Security Advisory. The ChainDrop analysis is drawn from the published Datadog Security Labs and Unit 42 reports and is credited to them, not independently reproduced._
