// Builds dist/brc-kit.js for BRC Pulse: drand checking and the giveaway code, from
// the same src/drand-core.js and src/giveaway-core.js that BRC Seal uses. Minified, one IIFE (global BRCKit).
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
const r = await build({ entryPoints: ['tools/kit-entry.js'], bundle: true, format: 'iife', globalName: 'BRCKit', target: ['es2020'], minify: true, legalComments: 'none', write: false });
let js = r.outputFiles[0].text.trim();
if (/<\/script/i.test(js)) throw new Error('bundle contains </script');
const notice = (p) => readFileSync(p, 'utf8').split('\n').find((l) => /copyright/i.test(l)).trim();
const libs = ['@noble/curves', '@noble/hashes', '@noble/ed25519', '@noble/ciphers', '@scure/bip39', '@scure/base'].map((n) => `${n}: ${notice(`node_modules/${n}/LICENSE`)}`).join('; ');
const header = `/*! BRC kit for BRC Pulse (from BRC Seal src/drand-core.js, src/giveaway-core.js and src/chain-core.js). MIT License. Includes ${libs}. */\n`;
mkdirSync('dist', { recursive: true });
writeFileSync('dist/brc-kit.js', header + js + '\n');
console.log(`dist/brc-kit.js ${((header + js).length / 1024).toFixed(1)} KB`);
