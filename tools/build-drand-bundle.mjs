// Builds dist/brc-drand.js: drand quicknet signature checking for BRC Pulse,
// from the same src/drand-core.js that BRC Post uses. Minified, one IIFE.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
const r = await build({ entryPoints: ['tools/drand-bundle.js'], bundle: true, format: 'iife', target: ['es2020'], minify: true, legalComments: 'none', write: false });
let js = r.outputFiles[0].text.trim();
if (/<\/script/i.test(js)) throw new Error('bundle contains </script');
const notice = (p) => readFileSync(p, 'utf8').split('\n').find((l) => /copyright/i.test(l)).trim();
const header = `/*! BRC drand verifier (from BRC Post src/drand-core.js). Includes @noble/curves and @noble/hashes, MIT License: ${notice('node_modules/@noble/curves/LICENSE')}; ${notice('node_modules/@noble/hashes/LICENSE')}. */\n`;
mkdirSync('dist', { recursive: true });
writeFileSync('dist/brc-drand.js', header + js + '\n');
console.log(`dist/brc-drand.js ${((header + js).length / 1024).toFixed(1)} KB`);
