/**
 * SAFE BY DESIGN.
 *
 * This file exists to prove one thing: a `preinstall` script in a dependency
 * runs arbitrary code on your machine, during `install`, before you have
 * imported anything or run a single line of your own program.
 *
 * It writes one marker file into the temp directory and prints a message.
 * It does not read, transmit, or modify anything else. The list of paths below
 * is a hardcoded string for illustration — nothing checks whether they exist
 * and nothing opens them.
 *
 * This is the exact position in the lifecycle that the ChainDrop / Shai-Hulud
 * worm used across 400+ npm packages on 4 August 2026. That payload was 727 KB
 * and did all the things this file deliberately does not.
 */

const { writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');

const marker = join(tmpdir(), 'angular-security-demo-PWNED.txt');

const banner = `
  ============================================================
   preinstall script executed
  ============================================================
   You ran a package manager. You did not run this code
   knowingly. It ran anyway, with your user's permissions.

   At this point a real payload would collect:
     ~/.npmrc              (npm publish token)
     ~/.ssh/id_*           (SSH keys)
     ~/.aws/credentials    (cloud credentials)
     ~/.config/gh/         (GitHub token)
     .env                  (whatever is in there)
     /proc/<pid>/mem       (CI runner secrets, never on disk)

   This demo read NONE of them. It only wrote:
     ${marker}
  ============================================================
`;

writeFileSync(
  marker,
  `Written by malicious-lib preinstall at ${new Date().toISOString()}\n` +
    `If this file exists, arbitrary code ran during install.\n`,
  'utf8',
);

console.log(banner);
