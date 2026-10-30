// Entry for the small drand verifier that BRC Pulse embeds (built by tools/build-drand-bundle.mjs).
import { verifyDrand, drandRoundTime, QUICKNET } from '../src/drand-core.js';
globalThis.BRCDrand = Object.freeze({ verifyDrand, drandRoundTime, QUICKNET });
