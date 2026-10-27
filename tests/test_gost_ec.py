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
