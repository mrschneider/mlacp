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

    NOT instantiated: the Appendix A.1 listing's integer-to-parameter
    mapping for the 256-bit set resisted verification (the generator does
    not satisfy the curve equation under any sign/assignment reading we
    tried) — the 512-bit set verifies completely and carries all the VKO
    test vectors, so it is the supported curve. See the README gap list."""
    raise NotImplementedError


CURVE_512A = _curve_512a()


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
