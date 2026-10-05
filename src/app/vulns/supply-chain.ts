import { Component } from '@angular/core';
import { CodeBlock } from '../shared/code-block';
import { VulnCard } from '../shared/vuln-card';

/**
 * The one attack on this list that does not care which framework you use.
 * It cannot be demonstrated in the browser, so this page points at a real
 * terminal demo in the repo instead.
 */
@Component({
  selector: 'app-supply-chain',
  imports: [CodeBlock, VulnCard],
  template: `
    <app-vuln-card
      status="live"
      heading="The npm worm that ignores your framework"
      summary="ChainDrop, 4 August 2026. Over 400 packages, some with 150M+ weekly downloads.
               Angular's sanitiser is irrelevant here — the code runs before your app exists."
    >
      <p>This was the entire change to the compromised package manifests:</p>
      <app-code-block [code]="manifest" language="json" label="Compromised package manifest" />
      <p>
        The library's real code was untouched. Tests passed. Behaviour was identical. One added
        lifecycle script, and <code>install</code> became remote code execution.
      </p>

      <h2>Run it yourself</h2>
      <p class="hint">
        This one needs a terminal, not a browser. The repo ships a harmless stand-in package that
        writes a single marker file to your temp directory and steals nothing:
      </p>
      <app-code-block [code]="command" language="bash" label="Supply-chain demo command" />
      <p>
        It installs the same package three times and shows that the outcome depends entirely on a
        package manager default: npm runs the script, <code>ignore-scripts</code> blocks it, and
        pnpm v10+ blocks it without being asked.
      </p>

      <h2>What the real payload did</h2>
      <p>
        From the
        <a
          href="https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/"
          target="_blank"
          rel="noopener noreferrer"
          >Datadog</a
        >
        and
        <a
          href="https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/"
          target="_blank"
          rel="noopener noreferrer"
          >Unit 42</a
        >
        analyses — I am citing their work, not malware:
      </p>
      <ul>
        <li>
          Downloaded Bun 1.3.13 from the genuine GitHub release, unverified, and ran a 727 KB
          obfuscated payload under it — because monitoring tuned to Node's internals does not watch
          Bun.
        </li>
        <li>
          Read GitHub Actions runner memory via <code>/proc/&lt;pid&gt;/mem</code>, collecting
          secrets that were never written to disk.
        </li>
        <li>
          Persisted through <code>.vscode/tasks.json</code> and a
          <code>.claude/settings.json</code> SessionStart hook, cross-linked so opening the project
          re-infects you. Nobody audits those files.
        </li>
        <li>
          Resolved its command-and-control domain from an Ethereum smart contract, so the operator
          rotated infrastructure with one transaction and no malware update.
        </li>
      </ul>

      <h2>The two findings that should change your habits</h2>
      <p>
        <strong>Valid provenance is not a verdict.</strong> One code path minted a genuine SLSA
        attestation through GitHub OIDC trusted publishing and signed it with Sigstore. It was not
        forged — the tarball really was built by that workflow. If the workflow is running attacker
        code, a valid signature is exactly what you should expect to see. Provenance tells you
        <em>where</em> a package came from, never whether it is clean.
      </p>
      <p>
        <strong>Rolling back the <code>latest</code> tag does not fix you.</strong> Your lockfile
        still pins the compromised version, and so do your CI image layers, package caches and
        internal mirror. Remediation means clearing caches, rebuilding images, regenerating the
        lockfile entry — and rotating every credential that machine could reach.
      </p>

      <h2>What to actually configure</h2>
      <app-code-block [code]="config" language="yaml" label="pnpm supply-chain configuration" />
      <p class="hint">
        <code>minimumReleaseAge</code> is the highest-leverage line here. Malicious versions are
        often caught quickly, so a one-day delay reduces exposure to short-lived campaigns. It is a
        time buffer, not a guarantee: an older compromised release still passes it. The setting is
        the default in pnpm v11 and opt-in on v10.
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
    ul {
      color: var(--text);
      padding-left: 20px;
    }
    li {
      margin-bottom: 8px;
    }
  `,
})
export class SupplyChain {
  protected readonly manifest = `{
  "scripts": {
    "preinstall": "node setup.mjs"
  }
}`;

  protected readonly command = `bash demo-supply-chain/run.sh`;

  protected readonly config = `# pnpm-workspace.yaml
minimumReleaseAge: 1440      # wait a day; v11 default, opt-in on v10
blockExoticSubdeps: true     # no transitive git/tarball sources
trustPolicy: no-downgrade    # refuse packages whose trust story got worse
onlyBuiltDependencies:       # explicit allowlist; 'allowBuilds' is v11-only
  - esbuild`;
}
