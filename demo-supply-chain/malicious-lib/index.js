/**
 * The package's "real" functionality, untouched and working.
 *
 * This is the part that matters about the ChainDrop compromise: the legitimate
 * code was left completely intact. Tests pass. Behaviour is identical. The only
 * change to the manifest was one added lifecycle script.
 */
module.exports.formatBytes = function formatBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${Math.round(n * 10) / 10} ${units[i]}`;
};
