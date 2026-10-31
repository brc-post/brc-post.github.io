// Prints the release message for a BRC Works file, to sign on the chain with the
// BRC Works release address (BRC Seal → Add my signature → My coin address).
// The signed block then goes in BRC Pulse's releases/ folder, so "Is this file
// genuine?" knows it.
//
//   node tools/release-message.mjs "BRC Vault" 1.1.0 ../vault/dist/brc-vault.html
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import { releaseMessage } from '../src/release-core.js';

const [tool, version, path] = process.argv.slice(2);
if (!tool || !version || !path) { console.error('Usage: node tools/release-message.mjs "<tool>" <version> <file>'); process.exit(1); }
const sha256 = createHash('sha256').update(readFileSync(path)).digest('hex');
process.stdout.write(releaseMessage({ tool, version, file: basename(path), sha256 }) + '\n');
