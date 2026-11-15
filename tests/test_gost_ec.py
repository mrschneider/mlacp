import pytest

from mlacp_core.gost_ec import CURVE_256A, CURVE_512A, Curve, vko

h = bytes.fromhex


def test_curve_512a_generator_on_curve():
    assert CURVE_512A.on_curve(CURVE_512A.g)


def test_curve_256a_generator_on_curve():
    """id-tc26-gost-3410-12-256-paramSetA: a cofactor-4 twisted Edwards
    curve in Weierstrass model — generator satisfies the equation, q·G = O
    and the full curve order is 4·q (verified at import and here)."""
    assert CURVE_256A.on_curve(CURVE_256A.g)
    assert CURVE_256A.scalar_mult(CURVE_256A.q) is None
    assert CURVE_256A.scalar_mult(4 * CURVE_256A.q) is None


def test_curve_generator_must_be_on_curve():
    with pytest.raises(ValueError):
        Curve("bad", CURVE_512A.p, CURVE_512A.a, CURVE_512A.b,
              CURVE_512A.m, CURVE_512A.q, 1, 1, 512)


def test_vko_symmetry_and_public_key_reproduction():
    """The agreement point derived by A equals the one derived by B, and the
    wire public keys reproduce from the private keys (RFC 7836 §B.7 data)."""
    c = CURVE_512A
    x_a = int.from_bytes(h(
        "c990ecd972fce84ec4db022778f50fcac726f46708384b8d458304962d7147f8"
        "c2db41cef22c90b102f2968404f9b9be6d47c79692d81826b32b8daca43cb667"), "little")
    y_b = int.from_bytes(h(
        "48c859f7b6f1158588 7cc05ec6ef1390cfea739b1a18c0d4662293ef63b79e3b"
        "8014070b449185 90b4b996acfea4edfbbbcccc8c06edd8bf5bda92a51392d0db".replace(" ", "")), "little")
    ukm = int.from_bytes(h("1d80603c8544c727"), "little")
    pub_a = c.public_key(x_a)
    pub_b = c.public_key(y_b)
    kek_a = vko(c, x_a, pub_b, ukm, bits=256)
    kek_b = vko(c, y_b, pub_a, ukm, bits=256)
    assert kek_a == kek_b
    assert kek_a == h(
        "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")


def test_vko_rejects_bad_bits():
    with pytest.raises(ValueError):
        vko(CURVE_512A, 1, CURVE_512A.g, 1, bits=128)


def _random_on_curve_point(c):
    """A random point on the curve (x random, y = a square root of the RHS)."""
    import os
    p = c.p
    while True:
        x = int.from_bytes(os.urandom(c.bits // 8), "little") % p
        rhs = (x * x * x + c.a * x + c.b) % p
        # p == 3 (mod 4): the square root is one exponentiation
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            return (x, y)


def _small_subgroup_point(c):
    """A point OUTSIDE the prime-order subgroup (order 2 or 4).

    ``q·R`` kills the prime-order part of a random on-curve ``R``, so the
    result lies in the small subgroup — but it can land on the IDENTITY,
    when ``R`` happened to be inside the prime-order subgroup itself.
    Picking a random ``R`` without checking is therefore FLAKY: the test
    failed in roughly half the runs. Retry until the small-subgroup
    component is non-zero.
    """
    for _ in range(64):
        R = _random_on_curve_point(c)
        Q = c.scalar_mult(c.q, R, reduce=False)
        if Q is not None:
            return Q
    raise AssertionError("could not build a small-subgroup point")  # pragma: no cover


def test_small_subgroup_points_are_refused_on_a_cofactor_curve():
    """A cofactor-4 curve has points of order 2 and 4 OUTSIDE the prime
    order subgroup. Accepting one as a peer public key makes the derived
    KEK predictable to whoever picked the point — the classic
    small-subgroup attack.

    The regression: the subgroup test used ``scalar_mult(q, P)``, and that
    path reduces the scalar modulo q — q mod q is 0, so the test answered
    "point at infinity" for EVERY point and the check was a tautology.
    The test now multiplies by the FULL q (no reduction)."""
    c = CURVE_256A
    assert c.m != c.q, "this curve is supposed to have a cofactor"
    Q = _small_subgroup_point(c)
    assert c.on_curve(Q), "the small-subgroup point is still on the curve"
    assert c.scalar_mult(c.q, Q, reduce=False) is not None, \
        "Q is NOT in the prime-order subgroup"
    assert not c.validate(Q), "a small-subgroup point must be refused"


def test_the_order_two_point_is_refused():
    """The 2-torsion point (y == 0) is the canonical small-subgroup point:
    it has order 2, so q·P = P ≠ O. It exists whenever the cubic
    x³ + a·x + b has a root modulo p."""
    c = CURVE_256A
    for x in range(0, 100000):
        if (x * x * x + c.a * x + c.b) % c.p == 0:
            break
    else:
        return  # no 2-torsion point on this curve: nothing to assert
    T = (x, 0)
    assert c.on_curve(T)
    assert c.scalar_mult(c.q, T, reduce=False) is not None
    assert not c.validate(T), "the 2-torsion point must be refused"


def test_the_prime_order_subgroup_is_still_accepted():
    """The fix must not break the legitimate path: a real public key
    (q·P = O) is still accepted."""
    for c in (CURVE_512A, CURVE_256A):
        d = 0x1234567890ABCDEF % c.q
        assert d > 0
        pub = c.public_key(d)
        assert c.validate(pub)


def test_cofactor_one_curve_skips_the_redundant_subgroup_test():
    """512A has m == q: the group order IS the prime order, so every
    on-curve point is in the prime-order subgroup and the test is
    mathematically redundant — the validation stays O(1)."""
    c = CURVE_512A
    assert c.m == c.q
    R = _random_on_curve_point(c)
    assert c.on_curve(R)
    assert c.validate(R), "on a cofactor-1 curve an on-curve point is valid"
    assert not c.validate(None), "the point at infinity is never a key"
    off_curve = (R[0], (R[1] + 1) % c.p)
    assert not c.validate(off_curve), "an off-curve point is refused"
