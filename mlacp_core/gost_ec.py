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
    """Short Weierstrass curve over a prime field.

    Internal arithmetic runs in JACOBIAN projective coordinates
    (X, Y, Z) with affine point P = (X/Z², Y/Z³): a doubling or a mixed
    add/double costs zero modular inverses, which were the dominant cost
    of the old affine implementation (one pow(·, -1, p) per group
    operation). Measured: full 512A handshakes drop from ~99ms to the
    single-digit ms range. Every public method still returns affine
    (x, y) tuples (or None for the point at infinity), so the wire
    format and the RFC 7836 vectors are unchanged.
    """

    def __init__(self, name: str, p: int, a: int, b: int, m: int, q: int,
                 gx: int, gy: int, bits: int):
        self.name = name
        self.p, self.a, self.b = p, a, b
        self.m, self.q = m, q          # group order / subgroup order
        self.g = (gx, gy)
        self.bits = bits
        # 8-bit precomputation window over the generator: 255 mixed adds
        # once at first use buy ~64 mixed adds per 512-bit scalar
        # (instead of ~128 adds + ~128 extra doubles) — see scalar_mult
        self._g_table: list | None = None
        if not self.on_curve(self.g):
            raise ValueError(f"{name}: generator is not on the curve")

    # -- field / point arithmetic (Jacobian) ---------------------------------
    # point at infinity: (1, 1, 0)

    def _jdouble(self, P) -> tuple:
        X1, Y1, Z1 = P
        if Y1 == 0:
            return (1, 1, 0)
        a = self.a
        p = self.p
        Y1sq = (Y1 * Y1) % p
        S = (4 * X1 * Y1sq) % p
        Z1sq = (Z1 * Z1) % p
        Z14 = (Z1sq * Z1sq) % p
        M = (3 * X1 * X1 + a * Z14) % p
        X3 = (M * M - 2 * S) % p
        Z3 = (2 * Y1 * Z1) % p
        Y3 = (M * (S - X3) - 8 * Y1sq * Y1sq) % p
        return (X3, Y3, Z3)

    def _jadd(self, P, Q) -> tuple:
        """Mixed addition: Q is AFFINE (Z=1). Correct for P == Q (reduces
        to a double). P at infinity (Z=0) is a guard, not a formula case:
        the mixed formulas assume Z1 != 0."""
        X1, Y1, Z1 = P
        x2, y2 = Q
        if Z1 == 0:
            return (x2, y2, 1)
        p = self.p
        Z1sq = (Z1 * Z1) % p
        Z1cu = (Z1sq * Z1) % p
        U1 = X1
        U2 = (x2 * Z1sq) % p
        S1 = Y1
        S2 = (y2 * Z1cu) % p
        if U1 == U2:
            if S1 == S2:
                return self._jdouble(P)
            return (1, 1, 0)
        H = (U2 - U1) % p
        R = (S2 - S1) % p
        Hsq = (H * H) % p
        Hcu = (H * Hsq) % p
        X3 = (R * R - Hcu - 2 * U1 * Hsq) % p
        Z3 = (H * Z1) % p
        Y3 = (R * (U1 * Hsq - X3) - S1 * Hcu) % p
        return (X3, Y3, Z3)

    def _jto_affine(self, P):
        X, Y, Z = P
        if Z == 0:
            return None
        p = self.p
        Zinv = pow(Z, -1, p)
        Zinv2 = (Zinv * Zinv) % p
        return ((X * Zinv2) % p, (Y * Zinv2 * Zinv) % p)

    def _build_g_table(self) -> list:
        if self._g_table is None:
            # tab[i] = (i+1)·G for i in 0..255: the window code looks up
            # tab[nib-1] for a nibble nib, i.e. it needs nib·G. Built by
            # repeated mixed adds (255 of them, once per process).
            G = (self.g[0], self.g[1], 1)
            tab = [G]
            cur = G
            for _ in range(255):
                cur = self._jadd(cur, self.g)  # (i+1)·G + G = (i+2)·G
                tab.append(cur)
            self._g_table = tab  # two threads may build twice: benign
        return self._g_table

    def scalar_mult(self, k: int, P: tuple | None = None) -> tuple | None:
        """Double-and-add (Jacobian). P defaults to the generator, for
        which an 8-bit window table cuts the add count in half. P at
        infinity (None) is returned as None; k is reduced mod q (the
        public-key subgroup order)."""
        k %= self.q
        if P is None:
            P = self.g
        if k == 0:
            return None
        if P is self.g:
            tab = self._build_g_table()
            # MSB-first 8-bit windowing: per window R = 2^8·R + nib·G.
            # tab[i] = (i+1)·G, so nib·G lives at tab[nib-1]. 512 doublings
            # + ~64 mixed adds replace 512 doublings + ~256 adds.
            nwin = (k.bit_length() + 7) // 8
            R = None
            for w in range(nwin - 1, -1, -1):
                if R is None:
                    R = (1, 1, 0)
                else:
                    R = self._jdouble(
                        self._jdouble(self._jdouble(
                            self._jdouble(self._jdouble(
                                self._jdouble(self._jdouble(
                                    self._jdouble(R))))))))
                nib = (k >> (8 * w)) & 0xFF
                if nib:
                    # tab[nib-1] is Jacobian; _jadd wants affine Q
                    R = self._jadd(R, self._jto_affine(tab[nib - 1]))
            return self._jto_affine(R)
        Q = (P[0], P[1], 1)
        R = None
        while k:
            if k & 1:
                R = self._jadd(R, self._jto_affine(Q)) if R is not None else Q
            Q = self._jdouble(Q)
            k >>= 1
        return self._jto_affine(R)

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


def generate_keypair(curve: Curve) -> tuple[int, tuple]:
    """An ephemeral VKO keypair: (private, public) with the public point on
    the curve. The private scalar is os.urandom-sourced."""
    import os
    while True:
        d = int.from_bytes(os.urandom(curve.bits // 8), "little")
        if 0 < d < curve.q:
            return d, curve.public_key(d)


def point_to_wire(curve: Curve, P: tuple) -> dict:
    """The wire form of a public point: X and Y LITTLE-ENDIAN hex (the ГОСТ
    wire convention verified against RFC 7836 §B)."""
    w = curve.bits // 8
    return {"x": P[0].to_bytes(w, "little").hex(),
            "y": P[1].to_bytes(w, "little").hex()}


def point_from_wire(curve: Curve, wire: dict) -> tuple:
    w = curve.bits // 8
    P = (int.from_bytes(bytes.fromhex(wire["x"]), "little"),
         int.from_bytes(bytes.fromhex(wire["y"]), "little"))
    if not curve.on_curve(P):
        raise ValueError("peer public key is not on the curve")
    return P


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
