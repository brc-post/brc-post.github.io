// Test bundle: everything the core tests need, from both cores.
export * from '../src/seal-core.js';
export { walletFromPrivateKeyHex, identifyInput, bytesToHex, hexToBytes } from '../src/vault-core.js';
export { encryptWallet } from '../src/vault-core.js';
export { ed25519 } from '@noble/curves/ed25519';
