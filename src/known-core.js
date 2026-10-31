// Naming official addresses, and catching look-alikes.
//
// BrowserCoin addresses have no typo check, and people compare only the start and
// the end. A scammer can grind out an address that shares those with an official
// one. So an address that matches an official address's first or last 6 characters,
// but isn't it, is flagged as a look-alike everywhere it appears.

import { sha256 } from '@noble/hashes/sha2';
import { hexToBytes } from './vault-core.js';
import { OFFICIAL } from './official.js';

const EDGE = 6;

/** The official entry for this exact address, or null. */
export function officialFor(address, list = OFFICIAL) {
  const a = String(address || '').toLowerCase();
  return list.find((o) => o.address === a) || null;
}

/**
 * The official entry this address imitates, or null: the same first 6 or last 6
 * characters, or the same first 4 and last 4 (what people actually glance at).
 */
export function lookalikeOf(address, list = OFFICIAL) {
  const a = String(address || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(a) || officialFor(a, list)) return null;
  return list.find((o) => o.address.slice(0, EDGE) === a.slice(0, EDGE) || o.address.slice(-EDGE) === a.slice(-EDGE)
    || (o.address.slice(0, 4) === a.slice(0, 4) && o.address.slice(-4) === a.slice(-4))) || null;
}

const PIC_COLORS = ['#5956fd', '#0d7a5f', '#e0552f', '#1f8fd6', '#c2417a', '#7c5cff', '#d99a0b', '#2f9e8f'];
/**
 * The small 3x3 address picture every BRC Works tool draws. It comes from SHA-256 of
 * the address, so an address made to share a few characters with another one still
 * gets an unrelated picture. Returns { colors: [9 CSS colours or 'transparent'] }.
 */
export function addressPicture(address) {
  const b = sha256(hexToBytes(String(address).toLowerCase(), 32));
  const c1 = PIC_COLORS[b[0] % 8];
  let c2 = PIC_COLORS[b[1] % 8];
  if (c2 === c1) c2 = PIC_COLORS[(b[1] + 3) % 8];
  const colors = [];
  for (let row = 0; row < 3; row++) {
    const left = b[2 + row] & 3, mid = b[5 + row] & 3;
    for (const v of [left, mid, left]) colors.push(v === 0 ? 'transparent' : v === 3 ? c2 : c1);
  }
  return { colors };
}

export { OFFICIAL };
