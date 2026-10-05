#!/usr/bin/env bash
#
# Installs the same harmless "compromised" package twice — once with npm, once
# with pnpm — and shows that the outcome differs entirely because of a default.
#
# Nothing here touches your real project, your credentials, or the network.
# Everything happens in a throwaway directory under /tmp.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$HERE/malicious-lib"
MARKER="${TMPDIR:-/tmp}/angular-security-demo-PWNED.txt"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/supply-chain-demo.XXXXXX")"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

hr() { printf '\n%s\n' "------------------------------------------------------------"; }

hr
echo " ROUND 1 — npm, default settings"
hr
rm -f "$MARKER"
mkdir -p "$WORK/npm-app"
printf '{"name":"victim","version":"1.0.0","private":true}\n' > "$WORK/npm-app/package.json"
( cd "$WORK/npm-app" && npm install --no-audit --no-fund "file:$LIB" 2>&1 | grep -vE '^npm (warn|notice)' )

if [ -f "$MARKER" ]; then
  echo ">> RESULT: the preinstall script RAN. Marker file exists:"
  echo "   $MARKER"
else
  echo ">> RESULT: no marker file. The script did not run."
fi

hr
echo " ROUND 2 — npm with ignore-scripts=true"
hr
rm -f "$MARKER"
mkdir -p "$WORK/npm-safe"
printf '{"name":"victim","version":"1.0.0","private":true}\n' > "$WORK/npm-safe/package.json"
printf 'ignore-scripts=true\n' > "$WORK/npm-safe/.npmrc"
( cd "$WORK/npm-safe" && npm install --no-audit --no-fund "file:$LIB" 2>&1 | grep -vE '^npm (warn|notice)' )

if [ -f "$MARKER" ]; then
  echo ">> RESULT: the preinstall script RAN."
else
  echo ">> RESULT: blocked. No marker file — ignore-scripts stopped it."
fi

hr
echo " ROUND 3 — pnpm, default settings (v10+)"
hr
rm -f "$MARKER"
mkdir -p "$WORK/pnpm-app"
printf '{"name":"victim","version":"1.0.0","private":true}\n' > "$WORK/pnpm-app/package.json"
printf 'packages:\n  - .\n' > "$WORK/pnpm-app/pnpm-workspace.yaml"
( cd "$WORK/pnpm-app" && pnpm add "file:$LIB" 2>&1 | tail -20 )

if [ -f "$MARKER" ]; then
  echo ">> RESULT: the preinstall script RAN."
else
  echo ">> RESULT: blocked. pnpm v10+ does not run dependency lifecycle scripts by default."
fi

hr
echo " Summary"
hr
cat <<'EOF'
Same package. Same payload. The only variable was a package manager default.

  npm, default            -> code ran
  npm, ignore-scripts     -> blocked
  pnpm v10+, default      -> blocked

To allow a build you actually need, on pnpm v10 use pnpm-workspace.yaml:

  onlyBuiltDependencies:
    - esbuild

Careful: the current pnpm docs say `allowBuilds`, but that name only exists in
v11. On v10 it is silently ignored — verify with:

  pnpm config get onlyBuiltDependencies --json

And the cheapest mitigation of all, which would have stopped ChainDrop:

  minimumReleaseAge: 1440    # wait one day before installing any new version
EOF
echo
