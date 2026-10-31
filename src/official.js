// Addresses that belong to BRC Works, by name. One list for every tool: BRC Seal and
// BRC Pulse (through the kit) show these names, and flag addresses that look like them.
//
// Each wallet is added here once it exists, in a release that is itself postmarked.
// Roles: 'release' signs every BRC Works release on the chain; 'mailbox' receives
// giveaway entries; 'pool' holds a prize pool.
export const OFFICIAL = Object.freeze([
  { address: '7ccb496c7bb6e78a169fdd3c2441772bc98730f3da43c3ee52046ee5e90caa00', name: 'BRC Works release address', role: 'release' },
  { address: 'b4b31b7337deecf2cd29d5ff22809520f819fa6b8ebfa05e029aa4709699997b', name: 'BRC Works giveaway mailbox', role: 'mailbox' },
  { address: '41210e34d2f518620d869caa0b097883f693c40649789eaf77edc4ae5f0758d1', name: 'BRC Works prize pool', role: 'pool' },
]);
