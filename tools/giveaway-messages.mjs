// Prints the messages the BRC Works release address signs on the chain for the giveaway
// (BRC Seal → Add my signature → My coin address, with the message pasted as is).
//
//   node tools/giveaway-messages.mjs launch ../pulse/giveaway/config.json
//     The rules: mailbox, prize pool, eligible list, entries close, draw round. Sign it when the
//     giveaway is announced, before entries open; add the signed block (with its Block: and
//     Lock ID: lines from BRC Pulse) to config.json as "launch".
//   The entry list is signed from BRC Seal → Open many letters → "Sign this list on the chain",
//   at least 6 hours before the draw; add that block to config.json as "commitment".
//   Don't sign anything else with the release address between the launch and the draw:
//   BRC Pulse requires exactly one lock by it in that window, the list.
import { readFileSync } from 'node:fs';
import { launchMessage, roundAt } from '../src/giveaway-core.js';

const [what, path] = process.argv.slice(2);
if (what !== 'launch' || !path) { console.error('Usage: node tools/giveaway-messages.mjs launch <config.json>'); process.exit(1); }
const g = JSON.parse(readFileSync(path, 'utf8'));
process.stdout.write(launchMessage({ mailbox: g.mailbox, pool: g.pool, eligible: g.eligible.fingerprint, closesAt: g.closesAt, round: roundAt(Math.floor(Date.parse(g.drawAt) / 1000)) }) + '\n');
