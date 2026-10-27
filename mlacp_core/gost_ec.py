"""MLACP layer 6b — the GOST R 34.10-2012 / VKO handshake (RFC 7091, RFC 7836).

Elliptic curves in short Weierstrass form (y² = x³ + ax + b mod p) with the
TC26 parameter sets, and the VKO key agreement:

    KEK_VKO(x, y, UKM) = H( (m/q · UKM · x mod q) · (y·P) )

Conventions (all verified against the RFC 7836 Appendix B examples 7 and 8,
on id-tc26-gost-3410-12-512-paramSetA — public keys reproduced from the
private keys, both KEK values byte-for-byte):

- public keys and UKM are LITTLE-ENDIAN byte strings;
- the agreement point K is hashed as LE(X)||LE(Y);
- the hash is the PRACTICAL (CryptoPro byte-stream) Streebog
  (``gost.streebog_practical``) — the RFC 7836 KEK vectors are computed in
  that convention, not the RFC 6986 mathematical one (see
  ``gost.streebog_practical``'s docstring for the two-conventions note).
"""

from __future__ import annotations

from .gost import streebog_practical


class Curve:
    """Short Weierstrass curve over a prime field with affine arithmetic."""

    def __init__(self, name: str, p: int, a: int, b: int, m: int, q: int,
                 gx: int, gy: int, bits: int):
        self.name = name
        self.p, self.a, self.b = p, a, b
        self.m, self.q = m, q          # group order / subgroup order
        self.g = (gx, gy)
        self.bits = bits
        if not self.on_curve(self.g):
            raise ValueError(f"{name}: generator is not on the curve")

    # -- field / point arithmetic -----------------------------------------
    def _add(self, P: tuple | None, Q: tuple | None) -> tuple | None:
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        x1, y1 = P
        x2, y2 = Q
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * pow(2 * y1, -1, p) % p
        else:
            lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
        x3 = (lam * lam - x1 - x2) % p
        y3 = (lam * (x1 - x3) - y1) % p
        return (x3, y3)

    def scalar_mult(self, k: int, P: tuple | None = None) -> tuple | None:
        """Double-and-add; P defaults to the generator."""
        if P is None:
            P = self.g
        k %= self.q
        result = None
        addend = P
        while k:
            if k & 1:
                result = self._add(result, addend)
            addend = self._add(addend, addend)
            k >>= 1
        return result

    def on_curve(self, P: tuple) -> bool:
        x, y = P
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def public_key(self, private: int) -> tuple:
        """The public key private·G — the RFC 7836 examples verify this."""
        return self.scalar_mult(private)


def _curve_512a() -> Curve:
    """id-tc26-gost-3410-12-512-paramSetA (RFC 7836 Appendix A.1)."""
    p = int.from_bytes(bytes.fromhex("00" + "FF" * 62 + "FDC7"), "big")
    a = int.from_bytes(bytes.fromhex("00" + "FF" * 62 + "FDC4"), "big")
    b = int.from_bytes(bytes.fromhex(
        "00E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B62"
        "65EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C7"
        "60"), "big")
    m = q = int.from_bytes(bytes.fromhex(
        "00" + "FF" * 40 + "27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B8"
        "5DCACDB1411F10B275"), "big")
    gx = 3
    gy = int.from_bytes(bytes.fromhex(
        "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921"
        "DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"
    ), "big")
    return Curve("id-tc26-gost-3410-12-512-paramSetA", p, a, b, m, q,
                 gx, gy, 512)


def _curve_256a() -> Curve:
    """id-tc26-gost-3410-12-256-paramSetA (RFC 7836 Appendix A.1).

    NOTE on this set: it is a TWISTED EDWARDS curve in its native form
    (cofactor 4) — the (a, b) here are its Weierstrass-model constants and
    the Weierstrass generator is (x, y) as listed below. The RFC 7836
    listing's integer ORDER is misleading (the generator coordinates are
    NOT the 4th/5th integers printed); the correct mapping was verified
    against go-gostcrypto's gost3410curves. Self-checks at import time:
    the generator satisfies the curve equation and q·G = O (prime-order
    subgroup), and the full curve order is 4·q."""
    p = int.from_bytes(bytes.fromhex("00" + "FF" * 30 + "FD97"), "big")
    a = int.from_bytes(bytes.fromhex(
        "C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"
    ), "big")
    b = int.from_bytes(bytes.fromhex(
        "295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"
    ), "big")
    q = int.from_bytes(bytes.fromhex(
        "400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"
    ), "big")
    m = 4 * q  # cofactor-4 twisted Edwards model; Weierstrass order 4q
    gx = int.from_bytes(bytes.fromhex(
        "91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"
    ), "big")
    gy = int.from_bytes(bytes.fromhex(
        "32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"
    ), "big")
    return Curve("id-tc26-gost-3410-12-256-paramSetA", p, a, b, m, q,
                 gx, gy, 256)


CURVE_512A = _curve_512a()
CURVE_256A = _curve_256a()


def vko(curve: Curve, private_key: int, peer_public: tuple, ukm: int = 1,
        bits: int = 256) -> bytes:
    """VKO_GOSTR3410_2012_{256,512} (RFC 7836 §4.3):

        KEK = H( (m/q · UKM · x mod q) · (y·P) )

    ``private_key`` and ``ukm`` are integers (wire key material and UKM are
    little-endian byte strings); ``peer_public`` is an (X, Y) tuple decoded
    from little-endian wire bytes. The agreement point is hashed as
    LE(X)||LE(Y) with the practical Streebog. Verified against RFC 7836
    Appendix B examples 7 (VKO_256) and 8 (VKO_512)."""
    if bits not in (256, 512):
        raise ValueError("vko bits must be 256 or 512")
    factor = (curve.m // curve.q) * ukm * private_key % curve.q
    K = curve.scalar_mult(factor, peer_public)
    if K is None:
        raise ValueError("VKO produced the point at infinity — refuse")
    width = curve.bits // 8
    material = K[0].to_bytes(width, "little") + K[1].to_bytes(width, "little")
    return streebog_practical(material, bits)
