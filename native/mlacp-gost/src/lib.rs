//! Native backend for MLACP's GOST layer (layer 6).
//!
//! Drop-in for the hot frame path of `mlacp_core.gost` (pure Python stays
//! the readable reference; the RFC vectors in `tests/test_gost.py` are the
//! conformance gate for BOTH backends).
//!
//! Ported function-for-function from the Python so the two stay in lockstep:
//! Kuznyechik (GOST R 34.12-2015 / RFC 7801), CNT mode (R 34.13-2015 §6.1),
//! MGM (RFC 9058) and the MLACP secure frame `iv || ct || tag`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

mod streebog;
mod streebog_tables;

// --- Kuznyechik parameters (RFC 7801 §4.1) --------------------------------

const PI: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219,
    147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129,
    28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212,
    211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112,
    14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154,
    199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
    128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185,
    3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115,
    30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
    165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217,
    231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113,
    103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244,
    180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
];

const L_COEF: [u8; 16] = [
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1,
];

const POLY8: u16 = 0x1C3; // p(x) = x^8 + x^7 + x^6 + x + 1 (RFC 7801 §3.2)

fn gf_mul(mut a: u16, mut b: u16) -> u8 {
    let mut r = 0u16;
    while b != 0 {
        if b & 1 != 0 {
            r ^= a;
        }
        b >>= 1;
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= POLY8;
        }
    }
    r as u8
}

fn sub_s(a: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = PI[a[i] as usize];
    }
    out
}

fn pi_inv_table() -> &'static [u8; 256] {
    static PI_INV: std::sync::OnceLock<[u8; 256]> = std::sync::OnceLock::new();
    PI_INV.get_or_init(|| {
        let mut inv = [0u8; 256];
        for (i, &v) in PI.iter().enumerate() {
            inv[v as usize] = i as u8;
        }
        inv
    })
}

fn sub_s_inv(a: &[u8; 16]) -> [u8; 16] {
    let inv = pi_inv_table();
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = inv[a[i] as usize];
    }
    out
}

fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn r_lin(a: &[u8; 16]) -> [u8; 16] {
    let mut l = 0u8;
    for i in 0..16 {
        l ^= gf_mul(L_COEF[i] as u16, a[i] as u16);
    }
    let mut out = [0u8; 16];
    out[0] = l;
    out[1..].copy_from_slice(&a[..15]);
    out
}

fn l_lin(a: &[u8; 16]) -> [u8; 16] {
    let mut t = *a;
    for _ in 0..16 {
        t = r_lin(&t);
    }
    t
}

fn r_inv(a: &[u8; 16]) -> [u8; 16] {
    // inverse of r_lin: l over the ROTATED vector, byte rotates the other way
    let mut rotated = [0u8; 16];
    rotated[..15].copy_from_slice(&a[1..]);
    rotated[15] = a[0];
    let mut l = 0u8;
    for i in 0..16 {
        l ^= gf_mul(L_COEF[i] as u16, rotated[i] as u16);
    }
    let mut out = [0u8; 16];
    out[..15].copy_from_slice(&a[1..]);
    out[15] = l;
    out
}

fn l_inv(a: &[u8; 16]) -> [u8; 16] {
    let mut t = *a;
    for _ in 0..16 {
        t = r_inv(&t);
    }
    t
}

fn lsx(k: &[u8; 16], a: &[u8; 16]) -> [u8; 16] {
    l_lin(&sub_s(&xor16(k, a)))
}

/// Fused S∘L tables: T[p][b] = L(S(b) placed at byte p, zeros elsewhere).
/// L(S(x)) = XOR over positions. Substitute ONLY the target byte (S(0) is
/// PI[0], not zero — folding it in from the other positions was the bug
/// class the RFC vectors caught in the Python port).
fn t_tables() -> &'static [[u128; 256]; 16] {
    static T: std::sync::OnceLock<[[u128; 256]; 16]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut tabs = [[0u128; 256]; 16];
        for p in 0..16 {
            for b in 0usize..256 {
                let mut blk = [0u8; 16];
                blk[p] = PI[b];
                tabs[p][b] = u128::from_be_bytes(l_lin(&blk));
            }
        }
        tabs
    })
}

fn lsx_fast(k: &[u8; 16], a: &[u8; 16]) -> [u8; 16] {
    let t = t_tables();
    let x = xor16(k, a);
    let mut r = 0u128;
    for p in 0..16 {
        r ^= t[p][x[p] as usize];
    }
    r.to_be_bytes()
}

/// Kuznyechik: 128-bit block, 256-bit key. Round keys precomputed once.
struct Kuznyechik {
    rk: [[u8; 16]; 10],
}

impl Kuznyechik {
    fn new(key: &[u8]) -> Result<Self, PyErr> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(
                "Kuznyechik key must be 32 bytes (V_256)",
            ));
        }
        // the 32 key-schedule constants are fixed by the standard:
        // C_i = L(i) with i as a 16-byte BIG-ENDIAN integer (RFC 7801 §4.3)
        let mut constants = [[0u8; 16]; 32];
        for i in 0u8..32 {
            let mut blk = [0u8; 16];
            blk[15] = i + 1;
            constants[i as usize] = l_lin(&blk);
        }
        let mut keys = [[0u8; 16]; 10];
        keys[0] = key[..16].try_into().unwrap();
        keys[1] = key[16..].try_into().unwrap();
        let mut a = keys[0];
        let mut b = keys[1];
        let mut k = 2;
        for i in 0..4 {
            for j in 0..8 {
                // f(c, a1, a0) = (xor(lsx(c, a1), a0), a1)
                let new_a = xor16(&lsx(&constants[8 * i + j], &a), &b);
                b = a;
                a = new_a;
            }
            keys[k] = a;
            keys[k + 1] = b;
            k += 2;
        }
        Ok(Kuznyechik { rk: keys })
    }

    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut t = *block;
        for k in self.rk.iter().take(9) {
            t = lsx_fast(k, &t);
        }
        xor16(&self.rk[9], &t)
    }

    fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut t = xor16(&self.rk[9], block); // strip X[K10]
        for k in self.rk[1..9].iter().rev() {
            // invert LSX[K9] .. LSX[K2]
            t = xor16(k, &sub_s_inv(&l_inv(&t)));
        }
        xor16(&self.rk[0], &sub_s_inv(&l_inv(&t))) // invert LSX[K1]
    }
}

// --- modes (ГОСТ Р 34.13-2015) ---------------------------------------------

fn inc_block(block: &mut [u8]) {
    // big-endian +1 over the full block
    for i in (0..block.len()).rev() {
        let (v, carry) = block[i].overflowing_add(1);
        block[i] = v;
        if !carry {
            return;
        }
    }
}

fn ctr_keystream_xor(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, PyErr> {
    if iv.len() != 16 {
        return Err(PyValueError::new_err("CTR IV must be a full 16-byte block"));
    }
    let cipher = Kuznyechik::new(key)?;
    let mut ctr = iv.to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let ks = cipher.encrypt_block(ctr[..16].try_into().unwrap());
        for (i, &b) in chunk.iter().enumerate() {
            out.push(b ^ ks[i]); // CTR consumes the keystream from its START
        }
        inc_block(&mut ctr);
    }
    Ok(out)
}

// --- MGM (RFC 9058) over Kuznyechik -----------------------------------------

const MGM_POLY_MSB: u128 = 0x87; // f(w) = w^128 + w^7 + w^2 + w + 1

fn mgm_dbl(x: u128) -> u128 {
    // u128 cannot hold bit 128: doubling drops the old bit 127, which is
    // exactly the bit that reduces with the 0x87 constant
    if x >> 127 != 0 {
        (x << 1) ^ MGM_POLY_MSB
    } else {
        x << 1
    }
}

fn mgm_mul(x: u128, y: u128) -> u128 {
    let mut r = 0u128;
    let mut a = x;
    for i in 0..128 {
        if (y >> i) & 1 != 0 {
            r ^= a;
        }
        a = mgm_dbl(a);
    }
    r
}

fn incr_r(b: &mut [u8]) {
    // right half (n/2 bytes) increments big-endian (RFC 9058)
    let n = b.len() / 2;
    for i in (b.len() - n..b.len()).rev() {
        let (v, carry) = b[i].overflowing_add(1);
        b[i] = v;
        if !carry {
            return;
        }
    }
}

fn incr_l(b: &mut [u8]) {
    let n = b.len() / 2;
    for i in (0..n).rev() {
        let (v, carry) = b[i].overflowing_add(1);
        b[i] = v;
        if !carry {
            return;
        }
    }
}

fn pad16(b: &[u8]) -> Vec<u8> {
    let rem = b.len() % 16;
    if rem == 0 {
        b.to_vec()
    } else {
        let mut v = b.to_vec();
        v.resize(v.len() + (16 - rem), 0u8);
        v
    }
}

fn mgm_tag(cipher: &Kuznyechik, icn: &[u8; 16], aad: &[u8], ct: &[u8], tag_len: usize) -> Vec<u8> {
    // z = E(0b1 || icn[1..])
    let mut z = [0u8; 16];
    z[0] = icn[0] | 0x80;
    z[1..].copy_from_slice(&icn[1..]);
    let mut z = cipher.encrypt_block(&z);
    let mut total = 0u128;
    for block in pad16(aad).chunks(16) {
        let h = u128::from_be_bytes(cipher.encrypt_block(&z));
        total ^= mgm_mul(h, u128::from_be_bytes(block.try_into().unwrap()));
        incr_l(&mut z);
    }
    for block in pad16(ct).chunks(16) {
        let h = u128::from_be_bytes(cipher.encrypt_block(&z));
        total ^= mgm_mul(h, u128::from_be_bytes(block.try_into().unwrap()));
        incr_l(&mut z);
    }
    let h = u128::from_be_bytes(cipher.encrypt_block(&z));
    let lens = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
    total ^= mgm_mul(h, lens);
    cipher.encrypt_block(&total.to_be_bytes())[..tag_len].to_vec()
}

fn mgm_encrypt(
    key: &[u8],
    icn: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    tag_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), PyErr> {
    if icn.len() != 16 || icn[0] & 0x80 != 0 {
        return Err(PyValueError::new_err(
            "MGM ICN must be 16 bytes with the top bit zero",
        ));
    }
    if !(1..=16).contains(&tag_len) {
        return Err(PyValueError::new_err(
            "MGM tag length must be 1..16 bytes (RFC 9058 §5.3)",
        ));
    }
    let cipher = Kuznyechik::new(key)?;
    let mut y = cipher.encrypt_block(icn.try_into().unwrap());
    let mut ct = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks(16) {
        let ks = cipher.encrypt_block(&y);
        for (i, &b) in block.iter().enumerate() {
            ct.push(b ^ ks[i]);
        }
        incr_r(&mut y);
    }
    let tag = mgm_tag(&cipher, icn.try_into().unwrap(), aad, &ct, tag_len);
    Ok((ct, tag))
}

// --- Python surface ----------------------------------------------------------

const MGM_AAD: &[u8] = b"mlacp-secure-frame-v1";

/// Constant-time byte-slice equality: folds the XOR of length-differing
/// (padded) bytes so verification timing does not leak how many tag bytes
/// matched. Length difference still shows (lengths are public on the wire);
/// content does not.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// KNOWN NON-CONSTANT-TIME behavior (documented, not fixed): the S-box and
// fused S∘L T-tables index memory by SECRET data, so accesses are
// cache-timing dependent — true of every table-driven software cipher and of
// the pure-Python reference a fortiori. Acceptable for MLACP's current
// threat model (peer-authenticated links, not hostile co-tenancy); revisit
// with bitsliced/table-free implementations if side channels enter the
// threat model.

#[pyfunction]
#[pyo3(signature = (key, iv, data))]
fn secure_encrypt(key: Vec<u8>, iv: Vec<u8>, data: Vec<u8>) -> PyResult<Vec<u8>> {
    let (ct, tag) = mgm_encrypt(&key, &iv, MGM_AAD, &data, 16)?;
    let mut out = Vec::with_capacity(16 + ct.len() + 16);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

#[pyfunction]
fn secure_decrypt(key: Vec<u8>, payload: Vec<u8>) -> PyResult<Vec<u8>> {
    if payload.len() < 32 {
        return Err(PyValueError::new_err(
            "secure frame too short — iv(16) || ct || tag(16)",
        ));
    }
    let icn = &payload[..16];
    let ct = &payload[16..payload.len() - 16];
    let tag = &payload[payload.len() - 16..];
    if icn[0] & 0x80 != 0 {
        return Err(PyValueError::new_err(
            "MGM ICN must be 16 bytes with the top bit zero",
        ));
    }
    let cipher = Kuznyechik::new(&key)?;
    let mut y = cipher.encrypt_block(icn.try_into().unwrap());
    let mut pt = Vec::with_capacity(ct.len());
    for block in ct.chunks(16) {
        let ks = cipher.encrypt_block(&y);
        // the MGM keystream is symmetric: plaintext = ct XOR keystream
        for (i, &b) in block.iter().enumerate() {
            pt.push(b ^ ks[i]);
        }
        incr_r(&mut y);
    }
    let expected = mgm_tag(&cipher, icn.try_into().unwrap(), MGM_AAD, ct, tag.len());
    if !ct_eq(&expected, tag) {
        return Err(PyValueError::new_err(
            "MGM tag verification failed — frame altered in transit",
        ));
    }
    Ok(pt)
}

/// Raw Kuznyechik block primitive (exposed for tests and future modes —
/// MGM itself never inverts a block).
#[pyfunction]
fn kuznyechik_encrypt_block(key: Vec<u8>, block: Vec<u8>) -> PyResult<Vec<u8>> {
    if block.len() != 16 {
        return Err(PyValueError::new_err(
            "Kuznyechik operates on 16-byte blocks",
        ));
    }
    let c = Kuznyechik::new(&key)?;
    let blk: [u8; 16] = block.try_into().unwrap();
    Ok(c.encrypt_block(&blk).to_vec())
}

#[pyfunction]
fn kuznyechik_decrypt_block(key: Vec<u8>, block: Vec<u8>) -> PyResult<Vec<u8>> {
    if block.len() != 16 {
        return Err(PyValueError::new_err(
            "Kuznyechik operates on 16-byte blocks",
        ));
    }
    let c = Kuznyechik::new(&key)?;
    let blk: [u8; 16] = block.try_into().unwrap();
    Ok(c.decrypt_block(&blk).to_vec())
}

#[pyfunction]
fn ctr_encrypt(key: Vec<u8>, iv: Vec<u8>, plaintext: Vec<u8>) -> PyResult<Vec<u8>> {
    ctr_keystream_xor(&key, &iv, &plaintext)
}

#[pyfunction]
fn ctr_decrypt(key: Vec<u8>, iv: Vec<u8>, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {
    ctr_keystream_xor(&key, &iv, &ciphertext)
}

#[pymodule]
fn mlacp_gost_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(secure_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(secure_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(streebog::streebog, m)?)?;
    m.add_function(wrap_pyfunction!(streebog::streebog_256, m)?)?;
    m.add_function(wrap_pyfunction!(streebog::streebog_512, m)?)?;
    m.add_function(wrap_pyfunction!(streebog::streebog_practical, m)?)?;
    m.add_function(wrap_pyfunction!(kuznyechik_encrypt_block, m)?)?;
    m.add_function(wrap_pyfunction!(kuznyechik_decrypt_block, m)?)?;
    m.add_function(wrap_pyfunction!(ctr_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ctr_decrypt, m)?)?;
    Ok(())
}

#[cfg(test)]
mod timing {
    use super::*;
    use std::time::Instant;

    #[test]
    fn block_speed() {
        let c = Kuznyechik::new(&[7u8; 32]).unwrap();
        let blk = [0x11u8; 16];
        // warm + build tables
        c.encrypt_block(&blk);
        let t = Instant::now();
        let n = 100_000;
        for _ in 0..n {
            std::hint::black_box(c.encrypt_block(std::hint::black_box(&blk)));
        }
        println!("encrypt_block: {:?} per block", t.elapsed() / n);
        // full frame path
        let data = vec![0x22u8; 4096];
        let icn = [0x01u8; 16];
        let t = Instant::now();
        let m = 200;
        for _ in 0..m {
            std::hint::black_box(mgm_encrypt(&key_vec(), &icn, b"aad", &data, 16).unwrap());
        }
        println!("mgm 4KB: {:?} per frame", t.elapsed() / m);
    }

    fn key_vec() -> Vec<u8> {
        vec![7u8; 32]
    }
}
