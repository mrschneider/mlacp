"""MLACP layer 6 — the GOST cryptographic layer.

Faithful implementation of the block cipher **Kuznyechik**
(GOST R 34.12-2015, RFC 7801): 128-bit block, 256-bit key, ten rounds of
LSX with the standard key schedule. Verified against every example of
RFC 7801 section 5 (S, R, L, key schedule, encryption, decryption).

On top of the block cipher, two modes are provided:

- ``ctr_encrypt`` / ``ctr_decrypt`` — counter mode (ГОСТ Р 34.13-2015 §6.1
  "CNT" shape: IV || counter, big-endian increment of the full block);
- ``cbc_mac`` — CBC-MAC over the whole message (simplified integrity;
  the full GOST R 34.13-2015 MAC with K^1/K^2 derivation is a documented gap).

NOT implemented (documented gaps): MGM authenticated mode (RFC 9058),
Streebog (RFC 6986), GOST R 34.10-2012 / VKO (RFC 7091, RFC 7836).
"""

# RFC 7801 §4.1 — the nonlinear bijection Pi' (256 values)
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

# RFC 7801 §4.1 — the inverse bijection Pi^(-1)'
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

# RFC 7801 §4.2 — the linear transformation l, coefficients on
# a_15..a_0 (first coefficient applies to the first byte of the string).
# The RFC text of §4.2 carries a typo ("148*delta(a_15) + 32*delta(a_15)");
# the intended coefficient vector is the symmetric one below, which the
# §5.2/§5.3 examples confirm.
L_COEF = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]

# p(x) = x^8 + x^7 + x^6 + x + 1  (RFC 7801 §3.2)
_POLY = 0x1C3


def _gf_mul(a: int, b: int) -> int:
    """Multiplication in the field Q = GF(2)[x]/p(x); bit i of an integer is
    the coefficient of x^i (RFC 7801 §3.2 element representation)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= _POLY
    return r


def _sub_s(a: bytes) -> bytes:
    """RFC 7801 §4.3 S: byte-wise substitution, string order preserved
    (verified by §5.1: S(ffeeddcc...) = b66cd888...)."""
    return bytes(PI[b] for b in a)


def _sub_s_inv(a: bytes) -> bytes:
    return bytes(PI_INV[b] for b in a)


def _r_lin(a: bytes) -> bytes:
    """RFC 7801 §4.3 R(a_15||...||a_0) = l(a_15,...,a_0) || a_15 || ... || a_1.

    The input string a[0..15] holds a_15 first; l is the field dot product
    of L_COEF with a."""
    l = 0
    for coef, byte in zip(L_COEF, a):
        l ^= _gf_mul(coef, byte)
    return bytes([l]) + a[:15]


def _l_lin(a: bytes) -> bytes:
    """RFC 7801 §4.3 L(a) = R^16(a)."""
    for _ in range(16):
        a = _r_lin(a)
    return a


def _r_inv(a: bytes) -> bytes:
    """RFC 7801 §4.3 R^(-1)(a_15||...||a_0) = a_14||...||a_0||l(a_14,...,a_0,a_15).

    The l argument is the input rotated left by one byte."""
    rotated = a[1:] + a[:1]
    l = 0
    for coef, byte in zip(L_COEF, rotated):
        l ^= _gf_mul(coef, byte)
    return a[1:] + bytes([l])


def _l_inv(a: bytes) -> bytes:
    """RFC 7801 §4.3 L^(-1)(a) = R^(-1) applied 16 times."""
    for _ in range(16):
        a = _r_inv(a)
    return a


def _lsx(k: bytes, a: bytes) -> bytes:
    return _l_lin(_sub_s(_xor128(k, a)))


def _xor128(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class Kuznyechik:
    """The GOST R 34.12-2015 cipher with the standard key schedule."""

    BLOCK = 16

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Kuznyechik key must be 32 bytes (V_256)")
        self._rk = self._key_schedule(key)

    # -- key schedule (RFC 7801 §4.4) ------------------------------------
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
        # F[k](a1,a0) = (LSX[k](a1) xor a0, a1)
        return _xor128(_lsx(c, a1), a0), a1

    # -- encryption / decryption (RFC 7801 §4.5) --------------------------
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
        # RFC 7801 §4.5.2: D(a) = X[K1] L^-1 S^-1 X[K2] ... L^-1 S^-1 X[K10].
        # Reading right to left: strip X[K10], then for k = K9..K2 apply
        # L^-1 S^-1 then X[k], and finally X[K1].
        t = _xor128(self._rk[9], b)  # strip X[K10]
        for k in reversed(self._rk[1:9]):  # invert LSX[K9] .. LSX[K2]
            t = _xor128(k, _sub_s_inv(_l_inv(t)))
        # invert LSX[K1]: the final S^-1 L^-1 belongs to it too
        return _xor128(self._rk[0], _sub_s_inv(_l_inv(t)))


# ---------------------------------------------------------------------------
# Modes (ГОСТ Р 34.13-2015 shapes)
# ---------------------------------------------------------------------------

def _inc(block: bytes) -> bytes:
    """Big-endian increment of the full block (mod 2^128)."""
    v = int.from_bytes(block, "big")
    v = (v + 1) % (1 << 128)
    return v.to_bytes(16, "big")


def ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """ГОСТ Р 34.13-2015 §6.1 CNT: keystream blocks E(IV||counter)."""
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
    return ctr_encrypt(key, iv, ciphertext)  # CTR is symmetric


def cbc_mac(key: bytes, data: bytes) -> bytes:
    """CBC-MAC over whole blocks: MAC = E(E(...E(data1)...)). The final
    partial block is zero-padded. (Simplified integrity layer — the full
    GOST R 34.13-2015 MAC derivation is a documented gap.)"""
    if len(data) % 16:
        data = data + b"\x00" * (16 - len(data) % 16)
    cipher = Kuznyechik(key)
    t = bytes(16)
    for off in range(0, len(data), 16):
        block = _xor128(t, data[off:off + 16])
        t = cipher.encrypt_block(block)
    return t


def secure_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """MLACP secure-frame payload: MAC(data) || CTR(data)."""
    return cbc_mac(key, data) + ctr_encrypt(key, iv, data)


def secure_decrypt(key: bytes, iv: bytes, payload: bytes) -> bytes:
    tag, ct = payload[:16], payload[16:]
    data = ctr_decrypt(key, iv, ct)
    if cbc_mac(key, data) != tag:
        raise ValueError("MAC verification failed — frame altered in transit")
    return data
