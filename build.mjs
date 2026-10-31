// Builds dist/brc-post.html: one self-contained file with all code inlined.
// Same approach as BRC Vault: readable code, embedded fonts, a single script
// locked by hash, no network access, and a reproducible build label.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';

const result = await build({
  entryPoints: ['src/app.js'],
  bundle: true,
  format: 'iife',
  target: ['es2020'],
  minify: false, // kept readable on purpose so anyone can review it
  legalComments: 'inline',
  write: false,
  // Test builds only: BRC_OFFICIAL names a JSON list that stands in for src/official.js,
  // so look-alike warnings can be tested before the real addresses exist.
  plugins: process.env.BRC_OFFICIAL ? [{
    name: 'test-official',
    setup(b) {
      b.onLoad({ filter: /src[\\/]official\.js$/ }, () => ({ contents: `export const OFFICIAL = Object.freeze(${JSON.stringify(JSON.parse(readFileSync(process.env.BRC_OFFICIAL, 'utf8')))});`, loader: 'js' }));
    },
  }] : [],
});
let js = result.outputFiles[0].text;
if (/<\/script/i.test(js)) js = js.replace(/<\/script/gi, '<\\/script');

const firstLine = (p) => readFileSync(p, 'utf8').split('\n').find((l) => /copyright/i.test(l))?.replace(/^\s*\/\/\s*/, '').trim();
const notices = [
  ['@noble/ed25519', 'node_modules/@noble/ed25519/LICENSE'],
  ['@noble/curves', 'node_modules/@noble/curves/LICENSE'],
  ['@noble/ciphers', 'node_modules/@noble/ciphers/LICENSE'],
  ['@noble/hashes', 'node_modules/@noble/hashes/LICENSE'],
  ['@scure/bip39', 'node_modules/@scure/bip39/LICENSE'],
  ['@scure/base', 'node_modules/@scure/base/LICENSE'],
].map(([name, path]) => ` * ${name} (MIT) — ${firstLine(path) || 'see project license'}`).join('\n')
  + `
 *
 * The MIT-licensed libraries above are provided under this notice:
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE.`;

const header = `/*!
 * BRC Post — sign, verify and seal messages with BrowserCoin addresses. MIT License.
 * Wallet loading is shared with BRC Vault (vault-core.js).
 * Includes these open-source libraries:
${notices}
 */
`;

// Geist and Geist Mono © Vercel, SIL Open Font License 1.1 (fonts/OFL-Geist.txt).
const font = (family, file) => `@font-face { font-family: "${family}"; font-style: normal; font-weight: 100 900; font-display: swap; src: url(data:font/woff2;base64,${readFileSync(file).toString('base64')}) format("woff2"); }`;
const fonts = [
  '/* Geist and Geist Mono © Vercel, SIL Open Font License 1.1 */',
  font('Geist', 'fonts/Geist-Variable.subset.woff2'),
  font('Geist Mono', 'fonts/GeistMono-Variable.subset.woff2'),
].join('\n');

const markInner = readFileSync('brand/mark-inner.txt', 'utf8').trim();
const markView = readFileSync('brand/brc-post-mark.svg', 'utf8').match(/viewBox="([^"]+)"/)[1];
const vaultMark = readFileSync('brand/vault-mark-ref.svg', 'utf8').match(/<svg[^>]*>([\s\S]*)<\/svg>/)[1].replace(/#353535/g, 'currentColor');
const favicon = 'data:image/svg+xml,' + encodeURIComponent(readFileSync('brand/brc-post-mark.svg', 'utf8').trim());

let html = readFileSync('src/index.html', 'utf8')
  .replaceAll('/*__MARK__*/', () => markInner)
  .replaceAll('/*__MARK_VIEW__*/', () => markView)
  .replace('/*__VAULT_MARK__*/', () => vaultMark)
  .replace('/*__FAVICON__*/', () => favicon)
  .replace('/*__FONTS__*/', () => fonts)
  .replace('/*__APP__*/', () => header + js);
const scriptBody = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const scriptHash = createHash('sha256').update(scriptBody, 'utf8').digest('base64');
html = html.replace("'__SCRIPT_HASH__'", `'sha256-${scriptHash}'`);
const buildId = createHash('sha256').update(scriptBody, 'utf8').digest('hex').slice(0, 8);
html = html.replace('/*__BUILD__*/', () => buildId);
const { version } = JSON.parse(readFileSync('package.json', 'utf8'));
if (!/^\d+\.\d+\.\d+(-test\.\d+)?$/.test(version)) throw new Error(`package.json version ${version} is not like 1.2.3 or 1.2.3-test.4`);
html = html.replace('/*__VERSION__*/', () => version);
// Test builds ask search engines to stay away: the site is live for testing but unlisted until a release.
const isTest = version.includes('-test');
if (isTest) html = html.replace('</title>', '</title>\n<meta name="robots" content="noindex, nofollow">');
if ((html.match(/<script/g) || []).length !== 1) throw new Error('Expected exactly one script tag');

if (process.env.BRC_OFFICIAL) {
  // A test build never replaces the real one.
  writeFileSync('build/brc-post-official-test.html', html);
  console.log('build/brc-post-official-test.html (test official list)');
  process.exit(0);
}
mkdirSync('dist', { recursive: true });
writeFileSync('dist/brc-post.html', html);
const sha = createHash('sha256').update(html).digest('hex');
writeFileSync('dist/SHA256.txt', `${sha}  brc-post.html\n`);
// The same file is served by GitHub Pages from docs/ (https://brc-post.github.io/).
mkdirSync('docs', { recursive: true });
writeFileSync('docs/index.html', html);
writeFileSync('docs/brc-post.html', html);
writeFileSync('docs/.nojekyll', '');
writeFileSync('docs/robots.txt', isTest ? 'User-agent: *\nDisallow: /\n' : 'User-agent: *\nAllow: /\n');
console.log(`dist/brc-post.html ${(html.length / 1024).toFixed(1)} KB  sha256 ${sha}`);
