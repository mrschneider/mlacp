"""ACPKM key meshing — verified against the OFFICIAL test examples of
draft-irtf-cfrg-re-keying-12 (Appendix A.2). The draft publishes AES-256
examples (no Kuznyechik vectors exist in the draft); the construction is
cipher-agnostic, so the AES wrapper exercises the exact same code path the
GOST ciphers use."""
import pytest

from mlacp_core.gost import ctr_acpkm_encrypt, ctr_acpkm_master, omac_acpkm_master

AES = pytest.importorskip("Crypto.Cipher.AES")

h = bytes.fromhex


class AESWrap:
    BLOCK = 16

    def __init__(self, key):
        self._c = AES.new(key, AES.MODE_ECB)

    def encrypt_block(self, b):
        return self._c.encrypt(b)


KEY = h("8899AABBCCDDEEFF0011223344556677FEDCBA98765432100123456789ABCDEF")
ICN = h("1234567890ABCEF00000000000000000")
PT112 = h("1122334455667700FFEEDDCCBBAA998800112233445566778899AABBCCEEFF0A"
          "112233445566778899AABBCCEEFF0A002233445566778899AABBCCEEFF0A0011"
          "33445566778899AABBCCEEFF0A001122445566778899AABBCCEEFF0A00112233"
          "5566778899AABBCCEEFF0A0011223344")


def test_ctr_acpkm_official_vector():
    """draft-12 A.2.1 CTR-ACPKM with AES-256 (k=256, n=128, N=256)."""
    ct = ctr_acpkm_encrypt(KEY, ICN, PT112, AESWrap, section_bytes=32)
    assert ct == h(
        "EC5CCBDE8C18D3B8725668D0A737F4581989E74232629D60997DE24BC0E39FB8"
        "F5AABA0BE364F053EEF0BC15C2764CEA9E7CC376BD8719C9770FCA2DE2A37CB5"
        "5B2B771BF83A0517BE042D8228FE2A95844E9F08FDF7B8944CB7AAB7DE3C67B4"
        "56B843FC3231DE46D5AB14F8AC09C739")
    assert ctr_acpkm_encrypt(KEY, ICN, ct, AESWrap, 32) == PT112  # self-inverse


def test_ctr_acpkm_master_official_vector():
    """draft-12 A.2.2 CTR-ACPKM-Master with AES-256 (N=256, T*=512)."""
    ct = ctr_acpkm_master(KEY, ICN, PT112, AESWrap,
                          section_bytes=32, master_chunk_bytes=64)
    assert ct == h(
        "9D8085C6F236123F7151D52B2433D4D4F6B787891C41789AAB459BD31EDB76AB"
        "5B256CC250E1051C8424C634DC0B2971010622FA07AA763E1BD3F3544F584AC6"
        "9B4D38DA9F33CB5665A2ED8FCB6684CA82B608F9D31B007F6A82EB87B1E7B9DC"
        "D74D9E8F0F9DFF599BC935A716DA7366")


def test_omac_acpkm_master_official_vector():
    """draft-12 A.2.2 OMAC-ACPKM-Master with AES-256 (T*=768, N=256)."""
    mac = omac_acpkm_master(KEY, PT112[:80], 16, AESWrap,
                            section_bytes=32, master_chunk_bytes=96)
    assert mac == h("B3ADB8921832054C0921E7B808CFA0B8")


def test_ctr_acpkm_kuznyechik_roundtrip():
    """The GOST instantiation shares the verified construction code path."""
    key = bytes(range(32))
    icn = bytes(range(16))
    pt = b"severnaya convoy schedule: section re-keying every 32 bytes" * 3
    ct = ctr_acpkm_encrypt(key, icn, pt)  # Kuznyechik, section 32
    assert ctr_acpkm_encrypt(key, icn, ct) == pt
