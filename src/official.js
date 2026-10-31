// Addresses that belong to BRC Works, by name. One list for every tool: BRC Seal and
// BRC Pulse (through the kit) show these names, and flag addresses that look like them.
//
// Each wallet is added here once it exists, in a release that is itself postmarked.
// Roles: 'release' signs every BRC Works release on the chain; 'mailbox' receives
// giveaway entries; 'pool' holds a prize pool.
export const OFFICIAL = Object.freeze([
  // { address: '<64 hex>', name: 'BRC Works release address', role: 'release' },
]);
