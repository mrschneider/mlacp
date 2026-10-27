"""GCM-ACPKM / GCM-ACPKM-Master — verified against the OFFICIAL test
examples of draft-irtf-cfrg-re-keying-12 Appendix A.2 (AES as the test
cipher; the construction is cipher-agnostic)."""
import pytest

from mlacp_core.gost import (
    gcm_acpkm_decrypt,
    gcm_acpkm_encrypt,
    gcm_acpkm_master_decrypt,
    gcm_acpkm_master_encrypt,
)

AES = pytest.importorskip("Crypto.Cipher.AES")
h = bytes.fromhex


class AESWrap:
    BLOCK = 16

    def __init__(self, key):
        self._c = AES.new(key, AES.MODE_ECB)

    def encrypt_block(self, b):
        return self._c.encrypt(b)


def test_gcm_acpkm_official_vector():
    """draft-12 A.2.1 GCM-ACPKM with AES-128 (k=128, N=256, c=32)."""
    ct, tag = gcm_acpkm_encrypt(h("00" * 16), h("00" * 12), h("112233"),
                                h("00" * 48), AESWrap, section_bytes=32)
    assert ct == h("0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF"
                   "948BC1E0D6B31246E9CE9FF13AB3427EE89196AD")
    assert tag == h("B00F155A60A36551868B53A2A41B7B66")


def test_gcm_acpkm_roundtrip_and_tamper():
    key, icn = bytes(range(16)), bytes(range(12))
    pt = b"convoy manifest: 3 trucks, winter route, sealed cargo" * 3
    ct, tag = gcm_acpkm_encrypt(key, icn, b"hdr", pt, AESWrap, 32)
    assert gcm_acpkm_decrypt(key, icn, b"hdr", ct, tag, AESWrap, 32) == pt
    with pytest.raises(ValueError, match="tag verification failed"):
        gcm_acpkm_decrypt(key, icn, b"hdr", bytes([ct[0] ^ 1]) + ct[1:], tag,
                          AESWrap, 32)


def test_gcm_acpkm_master_official_vector():
    """draft-12 A.2.2 GCM-ACPKM-Master with AES-192 (k=192, T*=384, N=256,
    c=32). The section keys are 192-bit chunks of the master material."""
    ct, tag = gcm_acpkm_master_encrypt(h("00" * 24), h("00" * 12), h("112233"),
                                       h("00" * 80), AESWrap, section_bytes=32,
                                       master_chunk_bytes=48)
    assert ct == h("43FA718164B1E3D71E7B6539A7021D52699B9E1B4324B7529574E790"
                   "F2BE60E81162C9902A2B777FD96AD61A99E0C6DE4B91D429E31A8C11"
                   "AFF0BC47F680AF14401CC11814638E762483377516347008")
    assert tag == h("CC3ABA118CE785FD777894D4B52069F8")


def test_gcm_acpkm_master_roundtrip():
    key, icn = bytes(range(24)), bytes(range(12))
    pt = b"stavka order: the meshed AEAD protects long dispatches" * 4
    ct, tag = gcm_acpkm_master_encrypt(key, icn, b"hdr", pt, AESWrap, 32,
                                       master_chunk_bytes=48)
    assert gcm_acpkm_master_decrypt(key, icn, b"hdr", ct, tag, AESWrap, 32,
                                    master_chunk_bytes=48) == pt
