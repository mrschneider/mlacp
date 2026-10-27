import pytest

from mlacp_core.gost import (
    Kuznyechik,
    Magma,
    ctr_decrypt,
    ctr_encrypt,
    gost_mac,
    mgm_decrypt,
    mgm_encrypt,
    secure_decrypt,
    secure_encrypt,
    streebog_256,
    streebog_512,
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


# -- Magma (GOST R 34.12-2015, param-Z S-boxes) ----------------------------------

def test_magma_official_vector():
    m = Magma(h("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
    assert m.encrypt_block(h("fedcba9876543210")) == h("4ee901e5c2d8ca3d")
    assert m.decrypt_block(h("4ee901e5c2d8ca3d")) == h("fedcba9876543210")


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


# -- MGM (RFC 9058) ----------------------------------------------------------------

def test_mgm_rfc_9058_a111_ciphertext():
    """RFC 9058 Appendix A.1.1 ciphertext. NOTE: the published A.1.1 A-block
    listing is internally inconsistent (the RFC's own tag-chain sums require
    an A of 42 bytes; the printed hexdump shows 41) — the ciphertext, which
    does not depend on the tag chain, matches byte for byte."""
    icn = h("1122334455667700ffeeddccbbaa9988")
    aad = h("02020202020202020101010101010101"
            "04040404040404040303030303030303"
            "ea050505050505050500000000000000"[:82])
    pt = h("1122334455667700ffeeddccbbaa9988"
           "00112233445566778899aabbcceeff0a"
           "112233445566778899aabbcceeff0a00"
           "2233445566778899aabbcceeff0a0011"
           "aabbcc")
    ct, _ = mgm_encrypt(KEY, icn, aad, pt)
    assert ct == h("a9757b8147956e9055b8a33de89f42fc"
                   "8075d2212bf9fd5bd3f7069aadc16b39"
                   "497ab15915a6ba85936b5d0ea9f6851c"
                   "c60c14d4d3f883d0ab94420695c76deb"
                   "2c7552")


def test_mgm_rfc_9058_a112_tag():
    """The A.1.2 vector: empty plaintext, 16-byte AAD — full tag check."""
    icn = h("1122334455667700ffeeddccbbaa9988")
    key = h("99aabbccddeeff0011223344556677fedcba98765432100123456789abcdef88")
    ct, tag = mgm_encrypt(key, icn, h("01" * 16), b"")
    assert ct == b""
    assert tag == h("7901e9ea2085cd247ed249695f9f8a85")


def test_mgm_roundtrip_and_tampering():
    key = bytes(range(32))
    iv = h("1122334455667700ffeeddccbbaa9988")
    pt = b"order: hold the line at all costs"
    ct, tag = mgm_encrypt(key, iv, b"hdr", pt)
    assert mgm_decrypt(key, iv, b"hdr", ct, tag) == pt
    with pytest.raises(ValueError, match="MGM tag verification failed"):
        mgm_decrypt(key, iv, b"hdr", bytes([ct[0] ^ 1]) + ct[1:], tag)


def test_mgm_icn_top_bit_reserved():
    with pytest.raises(ValueError):
        mgm_encrypt(KEY, h("ff" + "00" * 15), b"", b"")


# -- GOST R 34.13-2015 MAC (OMAC1/CMAC with K¹/K²) ----------------------------------

def test_gost_mac_official_a1_vector():
    P = h("1122334455667700ffeeddccbbaa9988"
          "00112233445566778899aabbcceeff0a"
          "112233445566778899aabbcceeff0a00"
          "2233445566778899aabbcceeff0a0011")
    assert gost_mac(KEY, P, tag_len=8) == h("336f4d296059fbe3")


def test_gost_mac_magma_variant_deterministic():
    mkey = h("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    data = b"dispatch order 47"
    assert gost_mac(mkey, data, cipher_cls=Magma, tag_len=8) == \
        gost_mac(mkey, data, cipher_cls=Magma, tag_len=8)


# -- Streebog (RFC 6986, mathematical convention) ------------------------------------

M1 = h("323130393837363534333231303938373635343332313039383736353433323130"
       "393837363534333231303938373635343332313039383736353433323130")
M2 = h("fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2"
       "f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202c"
       "e8f0f2e5e220e5d1")


def test_streebog_512_m1():
    assert streebog_512(M1) == h(
        "486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00"
        "fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b")


def test_streebog_256_m1():
    assert streebog_256(M1) == h(
        "00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d")


def test_streebog_512_m2():
    assert streebog_512(M2) == h(
        "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03"
        "7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e")


def test_streebog_256_m2():
    assert streebog_256(M2) == h(
        "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d")


def test_streebog_practical_matches_gostcrypto():
    """The practical (CryptoPro byte-stream) convention — verified against
    gostcrypto 1.2.5, the convention the RFC 7836 KEK vectors use."""
    gostcrypto = pytest.importorskip("gostcrypto")
    from mlacp_core.gost import streebog_practical
    for data in (b"", b"A", b"abc", bytes(range(63)), bytes(range(64)),
                 bytes(range(72)), bytes(range(200))):
        for bits in (256, 512):
            g = gostcrypto.gosthash.new(f"streebog{bits}")
            g.update(data)
            assert streebog_practical(data, bits) == g.digest()


# -- VKO (RFC 7836 §4.3, Appendix B examples 7 and 8) ---------------------------------

def test_vko_rfc_7836_examples():
    from mlacp_core.gost_ec import CURVE_512A, vko
    hx = lambda s: bytes.fromhex(s.replace(" ", "").replace("\n", ""))
    c = CURVE_512A
    pub_a = (int.from_bytes(hx(
        "aa b0 ed a4 ab ff 21 20 8d 18 79 9f b9 a8 55 66"
        "54 ba 78 30 70 eb a1 0c b9 ab b2 53 ec 56 dc f5"
        "d3 cc ba 61 92 e4 64 e6 e5 bc b6 de a1 37 79 2f"
        "24 31 f6 c8 97 eb 1b 3c 0c c1 43 27 b1 ad c0 a7"), "little"),
        int.from_bytes(hx(
        "91 46 13 a3 07 4e 36 3a ed b2 04 d3 8d 35 63 97"
        "1b d8 75 8e 87 8c 9d b1 14 03 72 1b 48 00 2d 38"
        "46 1f 92 47 2d 40 ea 92 f9 95 8c 0f fa 4c 93 75"
        "64 01 b9 7f 89 fd be 0b 5e 46 e4 a4 63 1c db 5a"), "little"))
    pub_b = (int.from_bytes(hx(
        "19 2f e1 83 b9 71 3a 07 72 53 c7 2c 87 35 de 2e"
        "a4 2a 3d bc 66 ea 31 78 38 b6 5f a3 25 23 cd 5e"
        "fc a9 74 ed a7 c8 63 f4 95 4d 11 47 f1 f2 b2 5c"
        "39 5f ce 1c 12 91 75 e8 76 d1 32 e9 4e d5 a6 51"), "little"),
        int.from_bytes(hx(
        "04 88 3b 41 4c 9b 59 2e c4 dc 84 82 6f 07 d0 b6"
        "d9 00 6d da 17 6c e4 8c 39 1e 3f 97 d1 02 e0 3b"
        "b5 98 bf 13 2a 22 8a 45 f7 20 1a ba 08 fc 52 4a"
        "2d 77 e4 3a 36 2a b0 22 ad 40 28 f7 5b de 3b 79"), "little"))
    x_a = int.from_bytes(hx(
        "c9 90 ec d9 72 fc e8 4e c4 db 02 27 78 f5 0f ca"
        "c7 26 f4 67 08 38 4b 8d 45 83 04 96 2d 71 47 f8"
        "c2 db 41 ce f2 2c 90 b1 02 f2 96 84 04 f9 b9 be"
        "6d 47 c7 96 92 d8 18 26 b3 2b 8d ac a4 3c b6 67"), "little")
    y_b = int.from_bytes(hx(
        "48 c8 59 f7 b6 f1 15 85 88 7c c0 5e c6 ef 13 90"
        "cf ea 73 9b 1a 18 c0 d4 66 22 93 ef 63 b7 9e 3b"
        "80 14 07 0b 44 91 85 90 b4 b9 96 ac fe a4 ed fb"
        "bb cc cc 8c 06 ed d8 bf 5b da 92 a5 13 92 d0 db"), "little")
    ukm = int.from_bytes(h("1d80603c8544c727"), "little")

    # the public keys are reproduced from the private keys (RFC 7836 §B.7)
    assert c.public_key(x_a) == pub_a
    assert c.public_key(y_b) == pub_b

    # example 7: VKO_GOSTR3410_2012_256
    assert vko(c, x_a, pub_b, ukm, bits=256) == h(
        "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")
    # example 8: VKO_GOSTR3410_2012_512
    assert vko(c, x_a, pub_b, ukm, bits=512) == h(
        "79f002a96940ce7bde3259a52e015297adaad84597a0d205b50e3e1719f97bfa"
        "7ee1d2661fa9979a5aa235b558a7e6d9f88f982dd63fc35a8ec0dd5e242d3bdf")
    # the agreement is symmetric (B derives the same KEK)
    assert vko(c, y_b, pub_a, ukm, bits=256) == h(
        "c9a9a77320e2cc559ed72dce6f47e2192ccea95fa648670582c054c0ef36c221")


# -- secure frames -------------------------------------------------------------------

def test_secure_frame_detects_tampering():
    iv = bytes(range(16))
    payload = secure_encrypt(KEY, iv, b"order: hold the line")
    tampered = bytes([payload[16] ^ 1]) + payload[17:]
    with pytest.raises(ValueError):
        secure_decrypt(KEY, payload[:16] + tampered)
    assert secure_decrypt(KEY, payload) == b"order: hold the line"
