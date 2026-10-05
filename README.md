# angular-security

An interactive Angular security lab with safe, versioned examples of common vulnerability classes.
This is not — and cannot be — a list of every possible Angular vulnerability.

## Live demo

[Open the Angular Security Lab](https://amosisa.github.io/angular-security/)

The GitHub Pages demo is a static, client-only build. It is safe to browse and deliberately does not
call the local `/api/profile` endpoint. The transfer-cache page explains the mechanism, but observing
the real SSR payload requires running the app locally.

> **Version warning:** this is a reproducible Angular 22.1.4 snapshot, not a current production
> baseline. Its pinned `@angular/platform-server` version is affected by
> [GHSA-f67j-2jqw-jpq7](https://github.com/angular/angular/security/advisories/GHSA-f67j-2jqw-jpq7),
> an SSR denial of service fixed in 22.1.6. Never deploy this repository's SSR server publicly.

## Run it

```bash
nvm use 24                 # Angular 22 needs Node ^22.22.3 || ^24.15.0 || >=26
pnpm install
pnpm start                 # dev server, client-side rendered
```

For the SSR demos (`/transfer-cache` needs a real server render):

```bash
pnpm build
pnpm serve:ssr             # http://localhost:4000
```

And the same build with defences switched on:

```bash
pnpm serve:ssr:hardened    # strict CSP + security headers
```

Open `/xss-bypass` in both. The payload fires in one and dies in the other, and the
vulnerable code is identical — that is the entire argument for CSP.

## The honest bit: what actually works

Every page is labelled, because the labels turned out to be the most interesting
thing about writing this.

| Label                         | Meaning                                                                                                                                                      |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Live demo pattern**         | A developer-created vulnerability that really executes in this versioned lab. It does not mean the installed Angular version is fully patched today.         |
| **Patched — mechanism shown** | The Angular bug is fixed, so the page demonstrates the underlying mechanism instead (real browser behaviour, real arithmetic) rather than faking an exploit. |
| **Blocked in this build**     | A payload this installed build stops. Included so you can watch the default working before watching people switch it off.                                    |

## What “Load demo admin token” means

It is not authentication and there is no real administrator account. The button writes the fixed
teaching value `tok_admin_9f2c` to `localStorage`. `FakeBackend` recognises that value as the
`admin` role so the XSS page can demonstrate two separate problems:

1. JavaScript injected through XSS can read a bearer token from Web Storage.
2. A stolen token can be replayed directly against an API without navigating through an Angular
   route guard.

Use **Sign out** to remove it. No real credential or external identity provider is involved.

### Live

| Page             | What it is                                                                                                          |
| ---------------- | ------------------------------------------------------------------------------------------------------------------- |
| `/xss-bypass`    | `bypassSecurityTrustHtml` on CMS input. Stage 1 of the attack chain.                                                |
| `/dom-injection` | `nativeElement.innerHTML`. Loses the sanitiser without calling a bypass, so a `bypassSecurityTrust` grep misses it. |
| `/guard-bypass`  | `canActivate` never runs when nobody navigates. Shows what actually saved you.                                      |
| `/supply-chain`  | ChainDrop. Points at the terminal demo below.                                                                       |

### Mechanism

| Page              | What it is                                                                                                                   |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `/transfer-cache` | Your SSR HTTP responses, embedded in the page. Also shows the SHA-256 cache key that fixed CVE-2026-54266, in your own HTML. |
| `/hash-collision` | Finds a real 32-bit DJB2 collision in your browser, in milliseconds.                                                         |
| `/dom-clobbering` | Two elements, one id, and which one `getElementById` returns.                                                                |

## The attack chain

The home page walks one bug becoming a breach. The point is that no single mistake
was fatal:

1. `bypassSecurityTrustHtml` on a CMS bio field → stored XSS
2. Payload reads the token from `localStorage` → credential theft
3. Payload calls the admin endpoint directly → the route guard was never in the request path
4. The stolen bearer token keeps working after the tab closes

Three reasonable-looking decisions. Remove any one of them and the chain breaks.

## Supply chain demo

```bash
bash demo-supply-chain/run.sh
```

Installs a deliberately harmless package with a `preinstall` script three times — npm
default, npm with `ignore-scripts`, and pnpm v10+ default — and reports which ones
executed it.

`demo-supply-chain/malicious-lib/preinstall.js` writes one marker file to your temp
directory and prints a message. It reads no credentials, opens no files and makes no
network requests. Read it before you run it; it is 40 lines.

## Things I verified while building this

Worth knowing, because two of them are not in the docs where you would look:

- **`autoCsp` and SSR are mutually exclusive.** The builder fails outright with
  `Cannot set both SSR and auto-CSP at the same time.` Hashes are for static builds;
  SSR needs a per-request nonce via `CSP_NONCE`. This app is SSR, so its hardened mode
  sets the CSP header in `server.ts`.
- **`security.allowedHosts` is load-bearing immediately.** With the CLI default of `[]`,
  SSR returns `400 Bad Request` for any host it does not recognise — including
  `localhost:4321`. That is Angular's SSRF protection, and it works.
- **`subresourceIntegrity` output lands in `index.csr.html`**, not `index.html`, when
  `outputMode` is `server`. Grepping the wrong file makes it look like the flag did
  nothing.
- **pnpm `allowBuilds` does not exist in v10.** The current pnpm docs recommend it, but
  it is a v11 name and is silently ignored on v10. Use `onlyBuiltDependencies` and check
  with `pnpm config get onlyBuiltDependencies --json`.

## Not demonstrated

Several advisories are documented rather than faked:

- **i18n ICU XSS** (CVE-2026-27970) needs a localised build and a hostile `.xlf`.
- **SSR raw-content serialisation** (CVE-2026-69149) needs a vulnerable `domino` and
  critical CSS inlining enabled.
- **Later SSR serializer bugs** involving processing instructions and `<template>` fragment
  boundaries are fixed in 22.1.4.
- **SSR URL-resolution SSRF** is fixed in 22.1.4.
- **Malformed-DOCTYPE SSR denial of service** is intentionally not executed because it locks the
  Node process. The installed 22.1.4 snapshot is affected; 22.1.6 is patched.

Reproducing patched issues means pinning a known-vulnerable version, and reproducing the DoS means
deliberately freezing the local server. Neither belongs in a click-to-run browser demo.

## Safety

Nothing here attacks anything you do not own. The "XSS" runs in your own browser tab
and reports to a panel on the page instead of exfiltrating to a server. The "malicious"
package writes one file to `/tmp`. There are no live payloads or real C2 addresses in executable form. The local SSR demo only calls
its own `/api/profile`; the public GitHub Pages build disables that request. The XSS trigger images
are hidden, so their intentionally invalid `src` values do not leave broken-image icons in the UI.

## Sources

The home page contains a complete, expandable source index for every Angular advisory represented
by the lab. It maps each vulnerability to its primary advisory and links implementation claims to
versioned Angular source code.

Core references:

- [Angular security guide](https://angular.dev/best-practices/security)
- [Angular route guard guide](https://angular.dev/guide/routing/route-guards)
- [Angular SSR guide](https://angular.dev/guide/ssr)
- [Angular security advisories](https://github.com/angular/angular/security/advisories)
- [pnpm supply-chain security guide](https://pnpm.io/supply-chain-security)

Sources and version claims were last checked on **16 September 2026**. Security information changes;
the linked advisories remain the authority for affected and patched versions.
