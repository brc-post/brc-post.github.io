// Naming official addresses, and catching look-alikes.
//
// BrowserCoin addresses have no typo check, and people compare only the start and
// the end. A scammer can grind out an address that shares those with an official
// one. So an address that matches an official address's first or last 6 characters,
// but isn't it, is flagged as a look-alike everywhere it appears.

import { OFFICIAL } from './official.js';

const EDGE = 6;

/** The official entry for this exact address, or null. */
export function officialFor(address, list = OFFICIAL) {
  const a = String(address || '').toLowerCase();
  return list.find((o) => o.address === a) || null;
}

/** The official entry this address imitates (same start or end, different address), or null. */
export function lookalikeOf(address, list = OFFICIAL) {
  const a = String(address || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(a) || officialFor(a, list)) return null;
  return list.find((o) => o.address.slice(0, EDGE) === a.slice(0, EDGE) || o.address.slice(-EDGE) === a.slice(-EDGE)) || null;
}

export { OFFICIAL };
