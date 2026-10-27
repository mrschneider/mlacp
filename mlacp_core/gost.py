"""MLACP layer 6 — the GOST cryptographic layer.

Faithful implementations, each verified against OFFICIAL test vectors:

- **Kuznyechik** (GOST R 34.12-2015, RFC 7801): 128-bit block, 256-bit key —
  every example of RFC 7801 §5 (S, R, L, key schedule, encrypt, decrypt);
- **Magma** (GOST R 34.12-2015, RFC 7801 with the id-tc26-gost-28147-param-Z
  S-boxes of RFC 7836 Appendix C): 64-bit block — the official test vector
  (key ffeeddcc…, plaintext fedcba9876543210 → 4ee901e5c2d8ca3d);
- **MGM** (GOST R 34.13-2015, RFC 9058): authenticated encryption with
  associated data over Kuznyechik — the full Appendix A.1.1 vector
  (ciphertext AND 128-bit tag);
- **Streebog** (GOST R 34.11-2012, RFC 6986): 256/512-bit hash — the
  §10.1 M1 vectors for both sizes;
- **GOST MAC** (GOST R 34.13-2015): the OMAC1/CMAC construction with the
  K¹/K² field doubling — verified through the RFC 7836 key-wrap example
  (CEK_MAC be33f052 under KEK_e with Magma);
- modes: CTR over Kuznyechik; secure frames are MGM with an AAD header.

Handshake (GOST R 34.10-2012 / VKO, RFC 7836) lives in ``gost_ec.py``.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Kuznyechik — parameters (RFC 7801 §4.1)
# ---------------------------------------------------------------------------

PI = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
    218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
    153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
    24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
    139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
    160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52,
    44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253,
    58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18,
    191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150,
    41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
    178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
    84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169,
    62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232,
    40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
    0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165,
    125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172,
    29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225,
    27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144,
    202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9,
    91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
    116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57,
    75, 99, 182,
]

PI_INV = [
    165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158,
    57, 85, 126, 82, 145, 100, 3, 87, 90, 28, 96,
    7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224,
    39, 141, 12, 130, 234, 174, 180, 154, 99, 73, 229,
    66, 228, 21, 183, 200, 6, 112, 157, 65, 117, 25,
    201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175,
    43, 134, 167, 177, 178, 91, 70, 211, 159, 253, 212,
    15, 156, 47, 155, 67, 239, 217, 121, 182, 83, 127,
    193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166,
    254, 172, 34, 249, 226, 74, 188, 53, 202, 238, 120,
    5, 107, 81, 225, 89, 163, 242, 113, 86, 17, 106,
    137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210,
    49, 222, 196, 95, 204, 207, 118, 44, 184, 216, 46,
    54, 219, 105, 179, 20, 149, 190, 98, 161, 59, 22,
    102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227,
    186, 241, 160, 133, 131, 218, 71, 197, 176, 51, 250,
    150, 111, 110, 194, 246, 80, 255, 93, 169, 142, 23,
    27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13,
    122, 103, 69, 135, 220, 232, 79, 29, 78, 4, 235,
    248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19,
    152, 2, 147, 128, 144, 208, 36, 52, 203, 237, 244,
    206, 153, 16, 68, 64, 146, 58, 1, 38, 18, 26,
    72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0,
    76, 215, 116,
]

# RFC 7801 §4.2 — coefficients on a_15..a_0 (the §4.2 text carries a known
# typo; this symmetric vector is what the §5.2/§5.3 examples confirm).
L_COEF = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

# p(x) = x^8 + x^7 + x^6 + x + 1  (RFC 7801 §3.2)
_POLY8 = 0x1C3


def _gf_mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= _POLY8
    return r


def _sub_s(a: bytes) -> bytes:
    return bytes(PI[b] for b in a)


def _sub_s_inv(a: bytes) -> bytes:
    return bytes(PI_INV[b] for b in a)


def _r_lin(a: bytes) -> bytes:
    l = 0
    for coef, byte in zip(L_COEF, a):
        l ^= _gf_mul(coef, byte)
    return bytes([l]) + a[:15]


def _l_lin(a: bytes) -> bytes:
    for _ in range(16):
        a = _r_lin(a)
    return a


def _r_inv(a: bytes) -> bytes:
    rotated = a[1:] + a[:1]
    l = 0
    for coef, byte in zip(L_COEF, rotated):
        l ^= _gf_mul(coef, byte)
    return a[1:] + bytes([l])


def _l_inv(a: bytes) -> bytes:
    for _ in range(16):
        a = _r_inv(a)
    return a


def _lsx(k: bytes, a: bytes) -> bytes:
    return _l_lin(_sub_s(_xor128(k, a)))


def _xor128(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class Kuznyechik:
    """GOST R 34.12-2015 cipher, 128-bit block, 256-bit key."""

    BLOCK = 16

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Kuznyechik key must be 32 bytes (V_256)")
        self._rk = self._key_schedule(key)

    def _key_schedule(self, key: bytes):
        k1, k2 = key[:16], key[16:]
        constants = [_l_lin(i.to_bytes(16, "big")) for i in range(1, 33)]
        keys = [k1, k2]
        a, b = k1, k2
        for i in range(4):
            for j in range(8):
                a, b = self._f(constants[8 * i + j], a, b)
            keys += [a, b]
        return keys

    def _f(self, c: bytes, a1: bytes, a0: bytes):
        return _xor128(_lsx(c, a1), a0), a1

    def encrypt_block(self, a: bytes) -> bytes:
        if len(a) != 16:
            raise ValueError("Kuznyechik operates on 16-byte blocks")
        t = a
        for k in self._rk[:9]:
            t = _lsx(k, t)
        return _xor128(self._rk[9], t)

    def decrypt_block(self, b: bytes) -> bytes:
        if len(b) != 16:
            raise ValueError("Kuznyechik operates on 16-byte blocks")
        t = _xor128(self._rk[9], b)  # strip X[K10]
        for k in reversed(self._rk[1:9]):  # invert LSX[K9] .. LSX[K2]
            t = _xor128(k, _sub_s_inv(_l_inv(t)))
        return _xor128(self._rk[0], _sub_s_inv(_l_inv(t)))  # invert LSX[K1]


# ---------------------------------------------------------------------------
# Magma — parameters (RFC 7801 + RFC 7836 Appendix C, param-Z S-boxes)
# ---------------------------------------------------------------------------

MAGMA_S = [
    [0xc, 0x6, 0xb, 0xc, 0x7, 0x5, 0x8, 0x1],
    [0x4, 0x8, 0x3, 0x8, 0xf, 0xd, 0xe, 0x7],
    [0x6, 0x2, 0x5, 0x2, 0x5, 0xf, 0x2, 0xe],
    [0x2, 0x3, 0x8, 0x1, 0xa, 0x6, 0x5, 0xd],
    [0xa, 0x9, 0x2, 0xd, 0x8, 0x9, 0x6, 0x0],
    [0x5, 0xa, 0xf, 0x4, 0x1, 0x2, 0x9, 0x5],
    [0xb, 0x5, 0xa, 0xf, 0x6, 0xc, 0x1, 0x8],
    [0x9, 0xc, 0xd, 0x6, 0xd, 0xa, 0xc, 0x3],
    [0xe, 0x1, 0xe, 0x7, 0x0, 0xb, 0xf, 0x4],
    [0x8, 0xe, 0x1, 0x0, 0x9, 0x7, 0x4, 0xf],
    [0xd, 0x4, 0x7, 0xa, 0x3, 0x8, 0xb, 0xa],
    [0x7, 0x7, 0x4, 0x5, 0xe, 0x1, 0x0, 0x6],
    [0x0, 0xb, 0xc, 0x3, 0xb, 0x4, 0xd, 0x9],
    [0x3, 0xd, 0x9, 0xe, 0x4, 0x3, 0xa, 0xc],
    [0xf, 0x0, 0x6, 0x9, 0x2, 0xe, 0x3, 0xb],
    [0x1, 0xf, 0x0, 0xb, 0xc, 0x0, 0x7, 0x2],
]


def _magma_sub(x: int) -> int:
    """Substitute the eight 4-bit nibbles (MSB first) through the param-Z
    boxes: the nibble i positions from the MSB goes through column K_{8-i}.
    Resolved against the official GOST R 34.12-2015 Magma test vector."""
    out = 0
    for i in range(8):
        nib = (x >> (4 * (7 - i))) & 0xF
        out = (out << 4) | MAGMA_S[nib][7 - i]
    return out


def _rol32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


class Magma:
    """GOST R 34.12-2015 cipher, 64-bit block, 256-bit key.

    Configuration resolved against the official test vector: big-endian
    word split, round keys k1..k8 for rounds 1-24 and k8..k1 for rounds
    25-32, substitution then rotate-left-11, and a swap on EVERY round
    (L, R) := (R, L ⊕ g(R)).
    """

    BLOCK = 8

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Magma key must be 32 bytes")
        self._k = [int.from_bytes(key[i * 4:i * 4 + 4], "big") for i in range(8)]
        self._rk = self._k * 3 + self._k[::-1]

    def _g(self, r: int, ki: int) -> int:
        t = (r + ki) & 0xFFFFFFFF
        return _rol32(_magma_sub(t), 11)

    def encrypt_block(self, a: bytes) -> bytes:
        if len(a) != 8:
            raise ValueError("Magma operates on 8-byte blocks")
        l = int.from_bytes(a[:4], "big")
        r = int.from_bytes(a[4:], "big")
        for i in range(31):  # rounds 1-31 swap
            l, r = r, l ^ self._g(r, self._rk[i])
        l = l ^ self._g(r, self._rk[31])  # round 32: no swap
        return l.to_bytes(4, "big") + r.to_bytes(4, "big")

    def decrypt_block(self, a: bytes) -> bytes:
        if len(a) != 8:
            raise ValueError("Magma operates on 8-byte blocks")
        l = int.from_bytes(a[:4], "big")
        r = int.from_bytes(a[4:], "big")
        # undo round 32 (no swap), then undo rounds 31..1
        l = l ^ self._g(r, self._rk[31])
        for i in range(30, -1, -1):
            l, r = r ^ self._g(l, self._rk[i]), l
        return l.to_bytes(4, "big") + r.to_bytes(4, "big")


# ---------------------------------------------------------------------------
# Modes (ГОСТ Р 34.13-2015 shapes)
# ---------------------------------------------------------------------------

def _inc(block: bytes) -> bytes:
    v = int.from_bytes(block, "big")
    v = (v + 1) % (1 << 128)
    return v.to_bytes(16, "big")


def ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """ГОСТ Р 34.13-2015 §6.1 CNT over Kuznyechik."""
    if len(iv) != 16:
        raise ValueError("CTR IV must be a full 16-byte block")
    cipher = Kuznyechik(key)
    ctr = iv
    out = bytearray()
    for off in range(0, len(plaintext), 16):
        ks = cipher.encrypt_block(ctr)
        chunk = plaintext[off:off + 16]
        out += bytes(x ^ y for x, y in zip(chunk, ks))
        ctr = _inc(ctr)
    return bytes(out)


def ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return ctr_encrypt(key, iv, ciphertext)


# ---------------------------------------------------------------------------
# MGM — RFC 9058, over Kuznyechik (n = 128)
# ---------------------------------------------------------------------------

# f(w) = w^128 + w^7 + w^2 + w + 1  (RFC 9058 §3); big-endian integer with
# bit i = w^i, so doubling reduces with 0x87.
_MGM_POLY_MSB = 0x87


def _mgm_dbl(x: int) -> int:
    x <<= 1
    if x >> 128:
        x = (x & ((1 << 128) - 1)) ^ _MGM_POLY_MSB
    return x


def _mgm_mul(x: int, y: int) -> int:
    """Field multiplication over GF(2^128), f(w) = w^128+w^7+w^2+w+1; bit i
    of the big-endian integer is the coefficient of w^i (RFC 9058 §3)."""
    r = 0
    a = x
    for i in range(128):
        if (y >> i) & 1:
            r ^= a
        a = _mgm_dbl(a)
    return r


def _incr_r(b: bytes) -> bytes:
    """RFC 9058: right half (n/2 bytes) increments big-endian."""
    n = len(b) // 2
    right = (int.from_bytes(b[n:], "big") + 1) % (1 << (8 * n))
    return b[:n] + right.to_bytes(n, "big")


def _incr_l(b: bytes) -> bytes:
    n = len(b) // 2
    left = (int.from_bytes(b[:n], "big") + 1) % (1 << (8 * n))
    return left.to_bytes(n, "big") + b[n:]


def _blocks(data: bytes):
    return [data[i:i + 16] for i in range(0, len(data), 16)]


def _mgm_tag(cipher: Kuznyechik, icn: bytes, aad: bytes, ct: bytes,
             tag_len: int) -> bytes:
    def pad(b: bytes) -> bytes:
        return b + b"\x00" * (16 - len(b) % 16) if len(b) % 16 else b
    z = cipher.encrypt_block(bytes([icn[0] | 0x80]) + icn[1:])
    total = 0
    for block in _blocks(pad(aad)):
        h = int.from_bytes(cipher.encrypt_block(z), "big")
        total ^= _mgm_mul(h, int.from_bytes(block, "big"))
        z = _incr_l(z)
    for block in _blocks(pad(ct)):
        h = int.from_bytes(cipher.encrypt_block(z), "big")
        total ^= _mgm_mul(h, int.from_bytes(block, "big"))
        z = _incr_l(z)
    h = int.from_bytes(cipher.encrypt_block(z), "big")
    lens = ((len(aad) * 8) << 64) | (len(ct) * 8)
    total ^= _mgm_mul(h, lens)
    return cipher.encrypt_block(total.to_bytes(16, "big"))[:tag_len]


def mgm_encrypt(key: bytes, icn: bytes, aad: bytes, plaintext: bytes,
                tag_len: int = 16) -> tuple[bytes, bytes]:
    """RFC 9058 §4.1 MGM over Kuznyechik. ``icn`` is the 16-byte initial
    counter nonce whose TOP BIT is zero (V_{n-1}); returns (ciphertext, tag).
    Verified against RFC 9058 Appendix A.1.1 (ciphertext and tag)."""
    if len(icn) != 16 or icn[0] & 0x80:
        raise ValueError("MGM ICN must be 16 bytes with the top bit zero")
    cipher = Kuznyechik(key)
    y = cipher.encrypt_block(icn)
    ct = bytearray()
    for block in _blocks(plaintext):
        ks = cipher.encrypt_block(y)
        ct += bytes(x ^ k for x, k in zip(block, ks))
        y = _incr_r(y)
    return bytes(ct), _mgm_tag(cipher, icn, aad, bytes(ct), tag_len)


def mgm_decrypt(key: bytes, icn: bytes, aad: bytes, ciphertext: bytes,
                tag: bytes) -> bytes:
    """RFC 9058 §4.2. Raises ValueError when the tag does not verify."""
    cipher = Kuznyechik(key)
    y = cipher.encrypt_block(icn)
    pt = bytearray()
    for block in _blocks(ciphertext):
        ks = cipher.encrypt_block(y)
        pt += bytes(x ^ k for x, k in zip(block, ks))
        y = _incr_r(y)
    if _mgm_tag(cipher, icn, aad, ciphertext, len(tag)) != tag:
        raise ValueError("MGM tag verification failed — frame altered in transit")
    return bytes(pt)


# ---------------------------------------------------------------------------
# GOST R 34.13-2015 MAC (the OMAC1/CMAC construction with K¹/K² doubling)
# ---------------------------------------------------------------------------

def gost_mac(key: bytes, data: bytes, cipher_cls=Kuznyechik,
             tag_len: int = 16) -> bytes:
    """GOST R 34.13-2015 MAC mode: OMAC1/CMAC over the given GOST cipher.
    K¹ = doubling of E(0^m) in GF(2^m) (f(w) = w^128+w^7+w^2+w+1 for
    Kuznyechik; w^64+w^4+w^3+w+1 for Magma); K² = doubling of K¹. The final
    complete block is XORed with K¹, an incomplete one is padded (0x80…00)
    and XORed with K². Verified through the RFC 7836 key-wrap example."""
    cipher = cipher_cls(key)
    m = cipher.BLOCK
    if cipher_cls is Kuznyechik:
        poly, width = 0x87, 128
    else:
        poly, width = 0x1B, 64  # f(w) = w^64 + w^4 + w^3 + w + 1

    def dbl(x: bytes) -> bytes:
        v = int.from_bytes(x, "big")
        v <<= 1
        if v >> width:
            v = (v & ((1 << width) - 1)) ^ poly
        return v.to_bytes(m, "big")

    k1 = dbl(cipher.encrypt_block(bytes(m)))
    k2 = dbl(k1)

    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    if not data:
        blocks = [bytes(m)]
        last_is_full = False
    else:
        blocks = [data[i:i + m] for i in range(0, len(data), m)]
        last_is_full = len(blocks[-1]) == m
    if last_is_full:
        last = xor(blocks[-1], k1)
    else:
        last_block = blocks[-1] + b"\x80" + b"\x00" * (m - len(blocks[-1]) - 1)
        last = xor(last_block, k2)
    t = bytes(m)
    for b in blocks[:-1]:
        t = cipher.encrypt_block(xor(t, b))
    return cipher.encrypt_block(xor(t, last))[:tag_len]


# ---------------------------------------------------------------------------
# secure frames (MLACP wiring) — now AEAD via MGM
# ---------------------------------------------------------------------------

MGM_AAD = b"mlacp-secure-frame-v1"


def secure_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """MLACP secure-frame payload: iv(16) || MGM ciphertext || tag(16),
    with the protocol header authenticated as associated data."""
    ct, tag = mgm_encrypt(key, iv, MGM_AAD, data)
    return iv + ct + tag


def secure_decrypt(key: bytes, payload: bytes) -> bytes:
    iv, ct, tag = payload[:16], payload[16:-16], payload[-16:]
    return mgm_decrypt(key, iv, MGM_AAD, ct, tag)


# ---------------------------------------------------------------------------
# Streebog — GOST R 34.11-2012 (RFC 6986)
# ---------------------------------------------------------------------------

TAU = [
    0, 8, 16, 24, 32, 40, 48, 56,
    1, 9, 17, 25, 33, 41, 49, 57,
    2, 10, 18, 26, 34, 42, 50, 58,
    3, 11, 19, 27, 35, 43, 51, 59,
    4, 12, 20, 28, 36, 44, 52, 60,
    5, 13, 21, 29, 37, 45, 53, 61,
    6, 14, 22, 30, 38, 46, 54, 62,
    7, 15, 23, 31, 39, 47, 55, 63,
]

STREEBOG_C = [
    "b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc"
    "4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507",
    "6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b50131"
    "9ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7",
    "f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7b"
    "d3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2",
    "ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353f"
    "a9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e",
    "4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbd"
    "bfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57",
    "ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6"
    "cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e",
    "f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c9"
    "0992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493",
    "9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49a"
    "f4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e",
    "378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984"
    "800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb",
    "abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b336103"
    "9fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced",
    "7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab07612001802114846679"
    "8a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b",
    "378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b"
    "5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720",
]


# RFC 6986 §6.4 — the 64x64 GF(2) matrix of l: V_64 -> V_64, row j = the
# 64-bit coefficient vector for output bit j (big-endian hex).
STREEBOG_L_ROWS = [
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
]


def _streebog_l64(group: bytes) -> bytes:
    """l: V_64 -> V_64 by RIGHT multiplication with the §6.4 matrix
    (out = v · A, i.e. output bit j sums column j). Input and output are
    8-byte big-endian vectors (bit 0 = rightmost)."""
    v = int.from_bytes(group, "big")
    out = 0
    for col in _streebog_l_cols():
        out = (out << 1) | (bin(v & col).count("1") & 1)
    return out.to_bytes(8, "big")


_COLS_CACHE: list[int] | None = None


def _streebog_l_cols() -> list[int]:
    """Columns of the §6.4 matrix as 64-bit masks (computed once)."""
    global _COLS_CACHE
    if _COLS_CACHE is None:
        cols = []
        for j in range(64):
            c = 0
            for k in range(64):
                c |= ((STREEBOG_L_ROWS[k] >> (63 - j)) & 1) << (63 - k)
            cols.append(c)
        _COLS_CACHE = cols
    return _COLS_CACHE


def _streebog_l(a: bytes) -> bytes:
    """RFC 6986 §7 L(a) = l(a_7)||...||l(a_0) over the eight V_64 groups."""
    return b"".join(_streebog_l64(a[i:i + 8]) for i in range(0, 64, 8))


def _streebog_p(a: bytes) -> bytes:
    """RFC 6986 §6.3/§7 P(a_63||...||a_0) = a_Tau(63)||...||a_Tau(0).
    Components enumerate from the RIGHT: a_k = byte[63-k]."""
    return bytes(a[63 - TAU[63 - j]] for j in range(64))


def _streebog_lps(a: bytes) -> bytes:
    return _streebog_l(_streebog_p(_sub_s(a)))


def _streebog_g(h: bytes, n: bytes, m: bytes) -> bytes:
    """RFC 6986 §8: g_N(h, m) = E(LPS(h ⊕ N), m) ⊕ h ⊕ m, with the 13-key
    schedule K[1] = LPS(h ⊕ N), K[i] = LPS(K[i-1] ⊕ C[i-1])."""
    ks = [_streebog_lps(_xor128(h, n))]
    for i in range(12):
        c = bytes.fromhex(STREEBOG_C[i])
        ks.append(_streebog_lps(_xor128(ks[-1], c)))
    t = m
    for k in ks[:12]:  # LPSX[K1] .. LPSX[K12]
        t = _streebog_lps(_xor128(t, k))
    # g_N(h, m) = E(...) ⊕ h ⊕ m
    return _xor128(ks[12], _xor128(t, _xor128(h, m)))


def streebog(message: bytes, bits: int = 256) -> bytes:
    """GOST R 34.11-2012 (RFC 6986). ``bits`` is 256 or 512. Verified
    against the §10.1 M1 vectors for both sizes."""
    if bits not in (256, 512):
        raise ValueError("streebog bits must be 256 or 512")
    if bits == 512:
        h = bytes(64)
    else:
        h = b"\x01" * 64  # RFC 6986 §7.1: IV = (00000001)^64, bit groups
    msg = message
    n = 0
    epsilon = 0
    while len(msg) >= 64:
        m = msg[-64:]           # the RIGHTMOST 512-bit block first
        msg = msg[:-64]
        h = _streebog_g(h, bytes(64), m)
        n += 512
        epsilon = (epsilon + int.from_bytes(m, "big")) % (1 << 512)
    # step 3.1: m = 0^(511-|M|) || 1 || M — the separator bit sits at bit
    # position |M| from the LSB, i.e. immediately ABOVE the message
    m_int = 1 << (8 * len(msg))
    m = m_int.to_bytes(64, "big")
    if msg:
        m = m[: 64 - len(msg)] + msg
    # §9 step 3.2 uses the N accumulated from the FULL blocks only (512 per
    # block); len(M) is added to N in step 3.3, AFTER g_N
    h = _streebog_g(h, n.to_bytes(64, "big"), m)
    n += len(msg) * 8  # step 3.3 adds the REMAINDER's length (|M| of step 3.1)
    epsilon = (epsilon + int.from_bytes(m, "big")) % (1 << 512)  # the PADDED block (§9 step 3.4)
    h = _streebog_g(h, bytes(64), n.to_bytes(64, "big"))
    h = _streebog_g(h, bytes(64), epsilon.to_bytes(64, "big"))
    return h[: bits // 8]


def streebog_256(message: bytes) -> bytes:
    return streebog(message, 256)


def streebog_512(message: bytes) -> bytes:
    return streebog(message, 512)


def _bswap64(b: bytes) -> bytes:
    """Reverse a 64-byte block (the practical↔mathematical bridge)."""
    return b[::-1]


def _add512_le(a: bytes, b: bytes) -> bytes:
    """Little-endian byte-wise addition mod 2^512 (the CryptoPro convention)."""
    out = bytearray(64)
    carry = 0
    for i in range(64):
        s = a[i] + b[i] + carry
        out[i] = s & 0xFF
        carry = s >> 8
    return bytes(out)


def streebog_practical(message: bytes, bits: int = 256) -> bytes:
    """The PRACTICAL (CryptoPro byte-stream) convention of GOST R 34.11-2012.

    Two conventions coexist for this standard: the RFC 6986 "mathematical"
    vector order (``streebog`` above — verified against the RFC §10 examples)
    and the practical byte-stream order used by CryptoPro tooling, where the
    message is processed first-block-first, the length counters add in
    little-endian, the padding follows the message, and the 256-bit IV is
    0^512. The RFC 7836 VKO test vectors are computed in the PRACTICAL
    convention — ``gost_ec.vko`` uses this function. The two conventions
    produce different digests for the same input; both are faithful ports,
    they just answer different questions.

    Verified byte-for-byte against gostcrypto 1.2.5 on empty/short/block-
    aligned/multi-block inputs for both digest sizes.
    """
    if bits not in (256, 512):
        raise ValueError("streebog bits must be 256 or 512")
    h = bytes(64) if bits == 512 else b"\x01" * 64  # practical 256-bit IV
    n = bytes(64)
    sigma = bytes(64)
    msg = message
    while len(msg) >= 64:
        block = msg[:64]          # FIRST block first (byte-stream order)
        msg = msg[64:]
        h = _bswap64(_streebog_g(_bswap64(h), _bswap64(n), _bswap64(block)))
        n = _add512_le(n, (512).to_bytes(64, "little"))
        sigma = _add512_le(sigma, block)
    pad = msg + b"\x01" + bytes(64 - len(msg) - 1)  # padding FOLLOWS the message
    h = _bswap64(_streebog_g(_bswap64(h), _bswap64(n), _bswap64(pad)))
    n = _add512_le(n, (len(msg) * 8).to_bytes(64, "little"))
    sigma = _add512_le(sigma, pad)
    h = _bswap64(_streebog_g(_bswap64(h), bytes(64), _bswap64(n)))
    h = _bswap64(_streebog_g(_bswap64(h), bytes(64), _bswap64(sigma)))
    return h[-(bits // 8):]


# ---------------------------------------------------------------------------
# ACPKM key meshing (R 1323565.1.017-2018; draft-irtf-cfrg-re-keying)
# ---------------------------------------------------------------------------

_ACPKM_D = bytes(range(0x80, 0xA0))  # first 256 bits of D (draft-12 §5)


def _ctr_blocks(cipher, iv: bytes, count: int):
    """CTR keystream blocks: block j = E(iv || counter_j), the counter is the
    LOW half of the block (n/2 bytes, big-endian) and the high half stays
    constant — the ГОСТ CTR convention."""
    n = cipher.BLOCK
    half = n // 2
    high = iv[:half]
    blocks = []
    ctr = 0
    for _ in range(count):
        blocks.append(cipher.encrypt_block(high + ctr.to_bytes(half, "big")))
        ctr += 1
    return blocks


def ctr_acpkm_encrypt(key: bytes, icn: bytes, plaintext: bytes,
                      cipher_cls=None, section_bytes: int = 32) -> bytes:
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    """CTR-ACPKM (R 1323565.1.017-2018 §6.2.2 / draft-12 §6.2.2): CTR with
    internal re-keying — the message is split into sections of
    ``section_bytes``; at every boundary the section key K^j is refreshed as
    K^j = E_{K^{j-1}}(D_1) || E_{K^{j-1}}(D_2) (D = 0x80..0x9F), while the
    CTR counter keeps running across sections. The initial key is K^1.
    Verified against the draft's official AES-256 test example (k=256, n=128,
    N=256: section keys F680D121…, 8EB97E43…, C5716CC9…)."""
    cipher = cipher_cls(key)
    m = cipher.BLOCK
    if len(icn) != m:
        raise ValueError("CTR-ACPKM ICN must be a full block")
    if section_bytes % m:
        raise ValueError("section size must be a multiple of the block size")
    blocks_per_section = section_bytes // m
    # D material for re-keying: k bytes = key length worth of D blocks
    j = -(-len(key) // m)  # ceil: keys not multiple of the block size take
    d_blocks = [_ACPKM_D[i * m:(i + 1) * m] for i in range(j)]  # MSB_k of the
    # concatenated D encryptions (ACPKM = MSB_k(E(D_1) || E(D_2) || …))
    out = bytearray()
    ctr = 0
    for section_start in range(0, len(plaintext), section_bytes):
        section = plaintext[section_start:section_start + section_bytes]
        for off in range(0, len(section), m):
            ks = cipher.encrypt_block(
                icn[:m // 2] + ctr.to_bytes(m // 2, "big"))
            out += bytes(x ^ y for x, y in zip(section[off:off + m], ks))
            ctr += 1
        # refresh the section key for the next section
        if section_start + section_bytes < len(plaintext):
            newkey = b"".join(cipher.encrypt_block(d) for d in d_blocks)
            cipher = cipher_cls(newkey[:len(key)])  # MSB_k
    return bytes(out)


def ctr_acpkm_decrypt(key: bytes, icn: bytes, ciphertext: bytes,
                      cipher_cls=Kuznyechik, section_bytes: int = 32) -> bytes:
    return ctr_acpkm_encrypt(key, icn, ciphertext, cipher_cls, section_bytes)


def ctr_acpkm_master(key: bytes, icn: bytes, plaintext: bytes,
                     cipher_cls=None, section_bytes: int = 32,
                     master_chunk_bytes: int = 64) -> bytes:
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    """CTR-ACPKM-Master (draft-12 §6.3.2): a CTR-ACPKM keyed with the MASTER
    key over zeros (re-keying itself every ``master_chunk_bytes`` = T*)
    generates the section keys K^1 | K^2 | ... (k bytes each); the message
    is encrypted in sections of ``section_bytes`` = N, the j-th section
    under K^j, the CTR counter running across the whole message.
    Verified against the draft's official AES-256 test example (N = 256,
    T* = 512)."""
    cipher = cipher_cls(key)
    m = cipher.BLOCK
    if len(icn) != m or section_bytes % m or master_chunk_bytes % len(key):
        raise ValueError("bad ICN/section/master sizes")
    n_sections = max(1, -(-len(plaintext) // section_bytes))
    material = ctr_acpkm_encrypt(
        key, b"\xff" * (m // 2) + b"\x00" * (m // 2),
        bytes(n_sections * len(key) + len(key)),
        cipher_cls, master_chunk_bytes)
    out = bytearray()
    ctr = 0
    for s in range(n_sections):
        sec = plaintext[s * section_bytes:(s + 1) * section_bytes]
        sec_cipher = cipher_cls(material[s * len(key):(s + 1) * len(key)])
        for off in range(0, len(sec), m):
            ks = sec_cipher.encrypt_block(
                icn[:m // 2] + ctr.to_bytes(m // 2, "big"))
            out += bytes(x ^ y for x, y in zip(sec[off:off + m], ks))
            ctr += 1
    return bytes(out)


def omac_acpkm_master(key: bytes, data: bytes, tag_len: int = 16,
                      cipher_cls=None, section_bytes: int = 32,
                      master_chunk_bytes: int = 96) -> bytes:
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    """OMAC-ACPKM-Master (draft-12 §6.3.6, the gost-engine construction):
    a CTR-ACPKM keyed with the MASTER key over zeros (re-keying itself
    every ``master_chunk_bytes`` = T*) generates the key material; every
    message section consumes (key_len + block) bytes of it:
    K^j = first key_len bytes, K^j_1 = the last block, which is the OMAC
    subkey L for that section (K² = doubling of K^j_1 in the field). The
    message is CBC-MAC'd section by section, chaining across boundaries.
    Verified against the draft's official AES-256 test example
    (T* = 768, N = 256, MAC = B3ADB8921832054C0921E7B808CFA0B8)."""
    cipher = cipher_cls(key)
    m = cipher.BLOCK
    if section_bytes % m:
        raise ValueError("section size must be a multiple of the block size")
    key_len = len(key)
    n_sections = max(1, -(-len(data) // section_bytes))
    km_stream = ctr_acpkm_encrypt(
        key, b"\xff" * (m // 2) + b"\x00" * (m // 2),
        bytes(n_sections * (key_len + m) + key_len),
        cipher_cls, master_chunk_bytes)

    def dbl(x: bytes) -> bytes:
        if cipher_cls is Kuznyechik:
            poly, width = 0x87, 128
        else:
            poly, width = 0x1B, 64
        v = int.from_bytes(x, "big") << 1
        if v >> width:
            v = (v & ((1 << width) - 1)) ^ poly
        return v.to_bytes(m, "big")

    def xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def mac_section(key_material: bytes, blocks: list[bytes],
                    chained: bytes, last: bool) -> bytes:
        """CBC-MAC of this section's blocks; for the FINAL block of the
        WHOLE message the OMAC K¹/K² XOR applies (padding 0x80…00)."""
        section_key = key_material[:key_len]
        sec_cipher = cipher_cls(section_key)
        l_sub = key_material[key_len:key_len + m]
        k1, k2 = l_sub, dbl(l_sub)
        result = chained
        for idx, b in enumerate(blocks):
            is_msg_final = last and idx == len(blocks) - 1
            if is_msg_final:
                if len(b) == m:
                    b = xor(b, k1)
                else:
                    b = xor(b + b"\x80" + b"\x00" * (m - len(b) - 1), k2)
            result = sec_cipher.encrypt_block(xor(result, b))
        return result

    sections = []
    for start in range(0, len(data), section_bytes):
        sections.append(data[start:start + section_bytes])
    if not sections:
        sections = [b""]
    chained = bytes(m)
    for i, section in enumerate(sections):
        material = km_stream[i * (key_len + m):(i + 1) * (key_len + m)]
        blocks = [section[k:k + m] for k in range(0, len(section), m)]
        chained = mac_section(material, blocks, chained, i == len(sections) - 1)
    return chained[:tag_len]


# ---------------------------------------------------------------------------
# GCM-ACPKM / GCM-ACPKM-Master (draft-12 §6.2.3 / §6.3.3)
# ---------------------------------------------------------------------------

def _pad16(b: bytes) -> bytes:
    return b + bytes(16 - len(b) % 16) if len(b) % 16 else b


_GCM_R = 0xE1 << 120


def _gcm_mul(x: int, y: int) -> int:
    """GCM field multiplication (NIST SP 800-38D convention, "by analogy
    with [GCM]" per the draft): the LEFTMOST bit of the block is the
    coefficient of x^0 — the OPPOSITE byte order to MGM's convention.
    f(w) = w^128 + w^7 + w^2 + w + 1, encoded 0xE1 || 0^120."""
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ _GCM_R if v & 1 else v >> 1
    return z


def _ghash(data_blocks: list[bytes], h_block: bytes) -> bytes:
    y = 0
    hv = int.from_bytes(h_block, "big")
    for b in data_blocks:
        y = _gcm_mul(y ^ int.from_bytes(b, "big"), hv)
    return y.to_bytes(16, "big")


def _gcm_acpkm_core(key: bytes, icn: bytes, aad: bytes, data: bytes,
                    cipher_cls, section_bytes: int, c: int, master: bool,
                    master_chunk_bytes: int | None, encrypt: bool):
    """Shared GCM-ACPKM/Master engine. Returns (ciphertext, tag); the GHASH
    ALWAYS runs over the ciphertext (GCTR input on decrypt, output on
    encrypt)."""
    cipher = cipher_cls(key)
    m = cipher.BLOCK
    if m != 16:
        raise ValueError("GCM-ACPKM requires a 128-bit block cipher")
    if len(icn) != m - c // 8:
        raise ValueError("ICN must be (n - c) bits")
    if section_bytes % m or (master_chunk_bytes and master_chunk_bytes % len(key)):
        raise ValueError("bad section/master sizes")

    def acpkm_keys(n_keys: int) -> list[bytes]:
        """Section keys. Internal mode: K^j = MSB_k(E_{K^{j-1}}(D_1)||…).
        Master mode: chunks of the ACPKM-Master material (a master-keyed
        CTR-ACPKM over zeros, re-keying itself every master_chunk_bytes)."""
        if not master:
            keys = [key]
            cur = key
            for _ in range(n_keys - 1):
                cc = cipher_cls(cur)
                material = b"".join(cc.encrypt_block(_ACPKM_D[i * m:(i + 1) * m])
                                    for i in range(-(-len(cur) // m)))
                cur = material[:len(key)]
                keys.append(cur)
            return keys
        material = ctr_acpkm_encrypt(
            key, b"\xff" * (m // 2) + b"\x00" * (m // 2),
            bytes(n_keys * len(key) + len(key)), cipher_cls, master_chunk_bytes)
        return [material[i * len(key):(i + 1) * len(key)] for i in range(n_keys)]

    def inc_c(block: bytes) -> bytes:
        low = (int.from_bytes(block[-c // 8:], "big") + 1) % (1 << c)
        return block[:-c // 8] + low.to_bytes(c // 8, "big")

    icb0 = icn + b"\x00" * (c // 8 - 1) + b"\x01"

    if master:
        n_sections = max(1, -(-len(data) // section_bytes))
        k1 = acpkm_keys(1)[0]
        keys = acpkm_keys(n_sections)
    else:
        k1 = key
        keys = acpkm_keys(max(1, -(-max(len(data), 1) // section_bytes)))

    h_block = cipher_cls(k1).encrypt_block(bytes(16))

    # GCTR: encrypt in sections, key per section
    out = bytearray()
    # GCTR starts at Inc_c(ICB_0) (the ICB_0 block itself is the tag mask)
    ctr_int = (int.from_bytes(icb0[-c // 8:], "big") + 1) % (1 << c)
    high = icb0[:-c // 8]
    for s_off in range(0, max(len(data), 1), section_bytes):
        sec = data[s_off:s_off + section_bytes]
        if master:
            sec_cipher = cipher_cls(keys[s_off // section_bytes])
        else:
            sec_cipher = cipher_cls(keys[min(len(keys) - 1,
                                             s_off // section_bytes)])
        for off in range(0, len(sec), m):
            ctr_block = high + ctr_int.to_bytes(c // 8, "big")
            ks = sec_cipher.encrypt_block(ctr_block)
            out += bytes(x ^ y for x, y in zip(sec[off:off + m], ks))
            ctr_int = (ctr_int + 1) % (1 << c)
    ct = bytes(out)

    lens = ((len(aad) * 8).to_bytes(8, "big") +
            (len(ct) * 8).to_bytes(8, "big"))
    pa, pc = _pad16(aad), _pad16(ct if encrypt else data)
    blocks = ([pa[i:i + m] for i in range(0, len(pa), m)] +
              [pc[i:i + m] for i in range(0, len(pc), m)] + [lens])
    s = _ghash(blocks, h_block)
    tag = bytes(x ^ y for x, y in zip(cipher_cls(k1).encrypt_block(icb0), s))
    return ct, tag[:16]


def gcm_acpkm_encrypt(key: bytes, icn: bytes, aad: bytes, plaintext: bytes,
                      cipher_cls=None, section_bytes: int = 32, c: int = 32,
                      tag_len: int = 16) -> tuple[bytes, bytes]:
    """GCM-ACPKM (draft-12 §6.2.3): GCM with internal ACPKM re-keying of the
    CTR section keys (H and the ICB_0 mask stay under the INITIAL key).
    Verified against the draft's official AES-128 test example (N = 256,
    c = 32)."""
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    ct, tag = _gcm_acpkm_core(key, icn, aad, plaintext, cipher_cls,
                              section_bytes, c, master=False,
                              master_chunk_bytes=None, encrypt=True)
    return ct, tag[:tag_len]


def gcm_acpkm_decrypt(key: bytes, icn: bytes, aad: bytes, ciphertext: bytes,
                      tag: bytes, cipher_cls=None, section_bytes: int = 32,
                      c: int = 32) -> bytes:
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    ct, computed = _gcm_acpkm_core(key, icn, aad, ciphertext, cipher_cls,
                                   section_bytes, c, master=False,
                                   master_chunk_bytes=None, encrypt=False)
    if computed[:len(tag)] != tag:
        raise ValueError("GCM-ACPKM tag verification failed")
    return ct


def gcm_acpkm_master_encrypt(key: bytes, icn: bytes, aad: bytes,
                             plaintext: bytes, cipher_cls=None,
                             section_bytes: int = 32, c: int = 32,
                             master_chunk_bytes: int = 48,
                             tag_len: int = 16) -> tuple[bytes, bytes]:
    """GCM-ACPKM-Master (draft-12 §6.3.3): section keys drawn from the
    ACPKM-Master material (a master-keyed CTR-ACPKM over zeros, re-keying
    itself every T* = ``master_chunk_bytes``); H and the ICB_0 mask are
    computed under K^1. Verified against the draft's official AES-192 test
    example (k = 192, T* = 384, N = 256, c = 32)."""
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    ct, tag = _gcm_acpkm_core(key, icn, aad, plaintext, cipher_cls,
                              section_bytes, c, master=True,
                              master_chunk_bytes=master_chunk_bytes, encrypt=True)
    return ct, tag[:tag_len]


def gcm_acpkm_master_decrypt(key: bytes, icn: bytes, aad: bytes,
                             ciphertext: bytes, tag: bytes, cipher_cls=None,
                             section_bytes: int = 32, c: int = 32,
                             master_chunk_bytes: int = 48) -> bytes:
    if cipher_cls is None:
        cipher_cls = Kuznyechik
    ct, computed = _gcm_acpkm_core(key, icn, aad, ciphertext, cipher_cls,
                                   section_bytes, c, master=True,
                                   master_chunk_bytes=master_chunk_bytes, encrypt=False)
    if computed[:len(tag)] != tag:
        raise ValueError("GCM-ACPKM-Master tag verification failed")
    return ct
