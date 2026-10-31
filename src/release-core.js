// Release postmarks: every BRC Works file that is published is described in a short
// message, and the BRC Works release address signs that message on the chain (as a
// chain-signed message, chain-core.js). BRC Pulse → "Is this file genuine?" hashes a
// file you have, finds its release, and checks the release address signed it.

const HEAD = 'BRC Works release v1';
const TOOLS = ['BRC Vault', 'BRC Pulse', 'BRC Seal', 'BRC Mailbox'];

/** The exact message to sign for a release. */
export function releaseMessage({ tool, version, file, sha256 }) {
  if (!TOOLS.includes(tool)) throw new Error(`Tool should be one of: ${TOOLS.join(', ')}.`);
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('A release version looks like 1.2.3 (test builds are never released).');
  if (!/^[A-Za-z0-9._-]{1,80}$/.test(file)) throw new Error('The file name should be plain, like brc-vault.html.');
  if (!/^[0-9a-f]{64}$/.test(sha256)) throw new Error('SHA-256 should be 64 characters, 0–9 and a–f.');
  return `${HEAD}\nTool: ${tool}\nVersion: ${version}\nFile: ${file}\nSHA-256: ${sha256}`;
}

/** If a (chain-signed) message is a release, read it. Otherwise null. */
export function readRelease(message) {
  const lines = String(message).split('\n');
  if (lines[0] !== HEAD || lines.length !== 5) return null;
  const get = (label) => (lines.find((l) => l.startsWith(label)) || '').slice(label.length).trim();
  const r = { tool: get('Tool:'), version: get('Version:'), file: get('File:'), sha256: get('SHA-256:') };
  try { return releaseMessage(r) === message ? r : null; } catch { return null; }
}
