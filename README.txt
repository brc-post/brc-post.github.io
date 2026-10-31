BRC Post (test build, not published)
====================================

Sign, verify and seal messages with BrowserCoin (BRC) addresses.
One offline web page: dist/brc-post.html. Open it in Chrome or Safari.
Nothing about you, your keys, letters or files is ever sent. Its one connection
is fetching the public drand time beacon when you postmark a file (untick
"Also prove when it was made" to skip it); the page can reach nothing else.

BRC Works: Vault (backups, https://pb-hash.github.io/brc-vault/) · Pulse (the live
BrowserCoin network dashboard, https://pb-hash.github.io/brc-pulse/) · Post.
Independent tools by pb-hash. Not part of the official BrowserCoin project.

What it does
------------
Sign    Your wallet signs a short statement. Anyone can check it, nobody can
        fake it or change a word. Uses: Discord miner roles, raffle entries,
        proving a pool payout address is yours.
Verify  Paste a signed block; the page says whether it is genuine and which
        address signed it. No wallet needed.
Seal    Encrypt a note to any BRC address. Post it anywhere; only that wallet
        can open it. Optionally sign it inside the encryption so only the
        recipient learns who sent it. No wallet needed for anonymous notes.
Open    Open a note sealed to your address. Needs that wallet.

"Use test wallets" makes two throwaway wallets, Alice and Bob, so every
feature can be tried without a real key.

Wallets load the same way as in BRC Vault: a BrowserCoin wallet file,
a private key or BRCKEY1 code, 24 recovery words, a BRC Vault backup, or a
BRC Wallet desktop backup. Keys stay in memory only and are wiped on
"Forget wallet" or when the page closes.

Formats (v1)
------------
Signed message: Ed25519 signature over
  "BrowserCoin Signed Message v1\nAddress: <64 hex>\nMessage:\n<message>"
The opening label means a message signature can never be a coin transaction
(transfers start with the chain id 0xc01dfeed, locks with "LOCK", script
redeems sign a 32-byte hash). Messages are normalised (NFC, LF line endings,
no trailing spaces, invisible characters removed) before signing and checking.
Signing refuses hidden or direction-changing characters, lines starting with
> or ``` (chat apps rewrite those), and look-alike BRC markers.
Verification is strict: canonical signatures only (zip215 off), and the
address must be a clean prime-order key. Small-order and torsioned addresses
are refused, so no address can "sign" without a real private key.

Sealed note: recipient Ed25519 key -> X25519; one-time X25519 key per note;
HKDF-SHA256(shared, salt = one-time key || recipient X25519 key,
info "BRC Post v1") -> 32-byte key + 24-byte nonce; XChaCha20-Poly1305 with
associated data "BRCSEAL1" || recipient address.
Body: version, flags, text length (2 bytes), a 96-byte sender slot (sender
address + signature, all zeros when anonymous, so signed and anonymous notes
are the same size), the text, zero padding to a multiple of 64 bytes.
The optional sender signature covers
"BrowserCoin Sealed Note v1\n" || recipient address || one-time key || text.
The recipient can show others that the sender wrote it.
Limit: no forward secrecy. If a wallet key leaks, past notes to it can be read.

Raffle (for BRC Pulse): entrants sign raffleEntryText(height). Only ELIGIBLE
addresses count (for example, addresses that mined a block before a snapshot
height announced in advance), because new wallets cost nothing. The organiser
publishes raffleListHash(entries) before the block, and drawRaffle refuses a
list that doesn't match it. Winner = sorted entries at
SHA-256("BRC raffle v1\n" + height + "\n" + block hash) mod count.
Keep the prize well under the 50 BRC block reward, so the block's miner has no
reason to throw away a block to change the result.

Build and test
--------------
  npm install
  npm test        core tests, independent Python/OpenSSL cross-check,
                  build, headless-browser page checks
  npm run build   writes dist/brc-post.html and dist/SHA256.txt

Builds are reproducible: the build label comes from the code, not the clock.

Status
------
Independent review (Oct 30, 2026): no critical or high findings. All medium
and low findings fixed, each with a regression test: keyless and torsioned
signatures (strict verification), raffle flooding (eligibility list, height
normalised, published list hash checked), an address pasted as a key (now needs
an explicit "this is my address" confirmation), messages that couldn't verify,
hidden characters, signed/anonymous size difference, and loader leftovers.

Test build. Not for real coins until it has had an outside security review.
