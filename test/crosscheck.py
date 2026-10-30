"""Independent cross-check of BRC Seal, written from the format description only.

Uses Python's `cryptography` library (OpenSSL), not the noble libraries the page
uses, to verify a signed message and open sealed notes made by the page.
The Edwards-to-Montgomery conversion and HChaCha20 are written out here by hand.

Usage: python3 test/crosscheck.py build/crosscheck.json
"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

P = 2**255 - 19

def ed_to_x_pub(ed_pub: bytes) -> bytes:
    y = int.from_bytes(ed_pub, 'little') & ((1 << 255) - 1)
    u = (1 + y) * pow(1 - y, P - 2, P) % P
    return u.to_bytes(32, 'little')

def ed_to_x_priv(seed: bytes) -> bytes:
    h = bytearray(hashlib.sha512(seed).digest()[:32])
    h[0] &= 248; h[31] &= 127; h[31] |= 64
    return bytes(h)

def rotl(v, c): return ((v << c) & 0xffffffff) | (v >> (32 - c))

def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574] + list(struct.unpack('<8I', key)) + list(struct.unpack('<4I', nonce16))
    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)
    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
    return struct.pack('<8I', *(s[0:4] + s[12:16]))

def xchacha_decrypt(key, nonce24, aad, ct):
    sub = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(sub).decrypt(b'\0\0\0\0' + nonce24[16:], ct, aad)

def verify_signed(block):
    lines = block.split('\n')
    i = lines.index('-----BEGIN BRC SIGNATURE-----')
    message = '\n'.join(lines[1:i])
    address = lines[i + 1].split(': ')[1]
    sig = bytes.fromhex(lines[i + 2].split(': ')[1])
    data = f'BrowserCoin Signed Message v1\nAddress: {address}\nMessage:\n{message}'.encode()
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(address)).verify(sig, data)  # raises if bad
    return address, message

def open_note(block, priv_hex):
    lines = block.split('\n')
    to = bytes.fromhex(lines[1][4:])
    payload = base64.b64decode(''.join(lines[3:-1]))
    assert payload[0] == 1
    eph, ct = payload[1:33], payload[33:]
    rec_x = ed_to_x_pub(to)
    seed = bytes.fromhex(priv_hex)
    my = X25519PrivateKey.from_private_bytes(ed_to_x_priv(seed))
    assert my.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == rec_x, 'key conversion mismatch'
    shared = my.exchange(X25519PublicKey.from_public_bytes(eph))
    okm = HKDF(algorithm=hashes.SHA256(), length=56, salt=eph + rec_x, info=b'BRC Seal v1').derive(shared)
    body = xchacha_decrypt(okm[:32], okm[32:], b'BRCSEAL1' + to, ct)
    signed = body[1] & 1
    n = (body[2] << 8) | body[3]
    start = 4 + 96  # sender slot is always reserved
    if not signed: assert all(b == 0 for b in body[4:100]), 'empty sender slot not zero'
    text = body[start:start + n]
    assert all(b == 0 for b in body[start + n:]), 'padding not zero'
    sender = None
    if signed:
        sender = body[4:36]
        sig = body[36:100]
        Ed25519PublicKey.from_public_bytes(sender).verify(sig, b'BrowserCoin Sealed Note v1\n' + to + eph + text)
    return text.decode(), sender.hex() if sender else None

fx = json.load(open(sys.argv[1]))
addr, msg = verify_signed(fx['signed'])
assert addr == fx['alice']['address'] and msg == 'Cross-check: signed by Alice.'
print('ok - signed message verifies with OpenSSL Ed25519')
text, sender = open_note(fx['anon'], fx['bob']['privateKeyHex'])
assert text == 'Cross-check: anonymous note to Bob. 🌱' and sender is None
print('ok - anonymous note opens with OpenSSL X25519 + hand-written XChaCha20-Poly1305')
text, sender = open_note(fx['fromAlice'], fx['bob']['privateKeyHex'])
assert text == 'Cross-check: signed note from Alice to Bob.' and sender == fx['alice']['address']
print('ok - signed note opens and its sender signature verifies')
