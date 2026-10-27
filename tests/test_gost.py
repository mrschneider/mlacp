import pytest

from mlacp_core.gost import (
    Kuznyechik,
    cbc_mac,
    ctr_decrypt,
    ctr_encrypt,
    secure_decrypt,
    secure_encrypt,
)

h = bytes.fromhex
KEY = h("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
PT = h("1122334455667700ffeeddccbbaa9988")
CT = h("7f679d90bebc24305a468d42b9d4edcd")


# -- RFC 7801 §5 official test values ------------------------------------------

def test_rfc_substitution():
    from mlacp_core.gost import _sub_s
    assert _sub_s(h("ffeeddccbbaa99881122334455667700")) == h(
        "b66cd8887d38e8d77765aeea0c9a7efc")


def test_rfc_linear_r():
    from mlacp_core.gost import _r_lin
    assert _r_lin(h("00000000000000000000000000000100")) == h(
        "94000000000000000000000000000001")


def test_rfc_linear_l():
    from mlacp_core.gost import _l_lin
    assert _l_lin(h("64a59400000000000000000000000000")) == h(
        "d456584dd0e3e84cc3166e4b7fa2890d")


def test_rfc_key_schedule():
    rk = [k.hex() for k in Kuznyechik(KEY)._rk]
    assert rk == [
        "8899aabbccddeeff0011223344556677",
        "fedcba98765432100123456789abcdef",
        "db31485315694343228d6aef8cc78c44",
        "3d4553d8e9cfec6815ebadc40a9ffd04",
        "57646468c44a5e28d3e59246f429f1ac",
        "bd079435165c6432b532e82834da581b",
        "51e640757e8745de705727265a0098b1",
        "5a7925017b9fdd3ed72a91a22286f984",
        "bb44e25378c73123a5f32f73cdb6e517",
        "72e9dd7416bcf45b755dbaa88e4a4043",
    ]


def test_rfc_encrypt_and_decrypt():
    cipher = Kuznyechik(KEY)
    assert cipher.encrypt_block(PT) == CT
    assert cipher.decrypt_block(CT) == PT


def test_key_length_enforced():
    with pytest.raises(ValueError):
        Kuznyechik(b"\x00" * 31)


# -- modes -----------------------------------------------------------------------

def test_ctr_roundtrip():
    iv = bytes(range(16))
    pt = b"vladivostok dispatch: winter convoy schedule" * 4
    ct = ctr_encrypt(KEY, iv, pt)
    assert ct != pt
    assert ctr_decrypt(KEY, iv, ct) == pt


def test_ctr_iv_must_be_block():
    with pytest.raises(ValueError):
        ctr_encrypt(KEY, b"\x00" * 15, b"data")


def test_cbc_mac_deterministic_and_length_sensitive():
    assert cbc_mac(KEY, b"alpha") == cbc_mac(KEY, b"alpha")
    assert cbc_mac(KEY, b"alpha") != cbc_mac(KEY, b"alphb")


def test_secure_frame_detects_tampering():
    iv = bytes(16)
    payload = secure_encrypt(KEY, iv, b"order: hold the line")
    # flip one bit of the ciphertext
    tampered = bytes([payload[16] ^ 1]) + payload[17:]
    with pytest.raises(ValueError, match="MAC verification failed"):
        secure_decrypt(KEY, iv, payload[:16] + tampered)
    assert secure_decrypt(KEY, iv, payload) == b"order: hold the line"
