//! Streebog — GOST R 34.11-2012 (RFC 6986), both conventions.
//!
//! Ported function-for-function from `mlacp_core.gost` (the readable
//! reference): `streebog` is the RFC 6986 "mathematical" order (rightmost
//! 512-bit block first, length counters big-endian), `streebog_practical`
//! is the CryptoPro byte-stream order used by the VKO test vectors. The two
//! produce different digests by design — they answer different questions.

use crate::streebog_tables::{STREEBOG_C, STREEBOG_L_ROWS, TAU};
use crate::PI;

fn l_cols() -> &'static [u64; 64] {
    // columns of the §6.4 matrix as 64-bit masks, derived from the rows
    // exactly like the Python _streebog_l_cols (l64 iterates COLUMNS, not
    // rows — iterating the rows was the first-port bug the vectors caught)
    static COLS: std::sync::OnceLock<[u64; 64]> = std::sync::OnceLock::new();
    COLS.get_or_init(|| {
        let mut cols = [0u64; 64];
        for (j, cj) in cols.iter_mut().enumerate() {
            let mut c = 0u64;
            for (k, row) in STREEBOG_L_ROWS.iter().enumerate() {
                c |= ((row >> (63 - j)) & 1) << (63 - k);
            }
            *cj = c;
        }
        cols
    })
}

fn l64(group: [u8; 8]) -> [u8; 8] {
    // out = v · A (out bit j sums column j); count_ones is native parity
    let v = u64::from_be_bytes(group);
    let mut out = 0u64;
    for col in l_cols() {
        let par = ((v & col).count_ones() & 1) as u64;
        out = (out << 1) | par;
    }
    out.to_be_bytes()
}

fn l(a: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..8 {
        let mut g = [0u8; 8];
        g.copy_from_slice(&a[i * 8..i * 8 + 8]);
        out[i * 8..i * 8 + 8].copy_from_slice(&l64(g));
    }
    out
}

fn p(a: &[u8; 64]) -> [u8; 64] {
    // components enumerate from the RIGHT: a_k = byte[63 - k]
    let mut out = [0u8; 64];
    for j in 0..64 {
        out[j] = a[63 - TAU[63 - j]];
    }
    out
}

fn s(a: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = PI[a[i] as usize];
    }
    out
}

fn lps(a: &[u8; 64]) -> [u8; 64] {
    l(&p(&s(a)))
}

fn xor64(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// g_N(h, m) = E(LPS(h ⊕ N), m) ⊕ h ⊕ m, K[1] = LPS(h ⊕ N),
/// K[i] = LPS(K[i-1] ⊕ C[i-1]) (RFC 6986 §8).
fn g(h: &[u8; 64], n: &[u8; 64], m: &[u8; 64]) -> [u8; 64] {
    let mut ks = [[0u8; 64]; 13];
    ks[0] = lps(&xor64(h, n));
    for i in 0..12 {
        let c = hex64(STREEBOG_C[i]);
        ks[i + 1] = lps(&xor64(&ks[i], &c));
    }
    let mut t = *m;
    for k in ks[..12].iter() {
        t = lps(&xor64(&t, k));
    }
    xor64(&ks[12], &xor64(&t, &xor64(h, m)))
}

fn hex64(hex: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// RFC 6986 "mathematical" convention: the RIGHTMOST 512-bit block is
/// processed first; verified against the §10.1 M1 vectors for both sizes.
pub fn streebog_core(message: &[u8], bits: usize) -> Result<Vec<u8>, PyErr> {
    if bits != 256 && bits != 512 {
        return Err(PyValueError::new_err("streebog bits must be 256 or 512"));
    }
    let mut h = if bits == 512 {
        [0u8; 64]
    } else {
        [0x01u8; 64] // §7.1: IV = (00000001)^64, bit groups
    };
    let mut msg = message;
    let mut n: u128 = 0;
    let mut epsilon = [0u8; 64]; // 512-bit big-endian accumulator
    while msg.len() >= 64 {
        let m: &[u8] = &msg[msg.len() - 64..];
        msg = &msg[..msg.len() - 64];
        h = g(&h, &[0u8; 64], m.try_into().unwrap());
        n += 512;
        // epsilon += m (mod 2^512), big-endian byte-wise with carry
        let mut carry = 0u16;
        for i in (0..64).rev() {
            let s = epsilon[i] as u16 + m[i] as u16 + carry;
            epsilon[i] = s as u8;
            carry = s >> 8;
        }
    }
    // step 3.1: m = 0^(511-|M|) || 1 || M — the separator sits immediately
    // ABOVE the message
    let mut m = [0u8; 64];
    let rem = msg.len();
    m[63 - rem] = 0x01;
    m[64 - rem..].copy_from_slice(msg);
    // step 3.2 uses the N accumulated from FULL blocks only; len(M) joins
    // N in step 3.3, AFTER g_N
    let mut n_full = [0u8; 64];
    n_full[56..].copy_from_slice(&(n as u64).to_be_bytes());
    h = g(&h, &n_full, &m);
    n += rem as u128 * 8; // step 3.3 adds the REMAINDER's length
    epsilon = add512_be(&epsilon, &m); // §9 step 3.4: the PADDED block
    n_full[56..].copy_from_slice(&(n as u64).to_be_bytes());
    h = g(&h, &[0u8; 64], &n_full);
    h = g(&h, &[0u8; 64], &epsilon);
    Ok(h[..bits / 8].to_vec())
}

fn add512_be(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut carry = 0u16;
    for i in (0..64).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    out
}

fn bswap64(b: &[u8; 64]) -> [u8; 64] {
    let mut out = *b;
    out.reverse();
    out
}

fn add512_le(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    // little-endian byte-wise addition mod 2^512 (the CryptoPro convention)
    let mut out = [0u8; 64];
    let mut carry = 0u16;
    for i in 0..64 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    out
}

/// The PRACTICAL (CryptoPro byte-stream) convention: first block first,
/// length counters little-endian, padding FOLLOWS the message, 256-bit IV
/// is 0^512. The RFC 7836 VKO test vectors use this convention.
pub fn streebog_practical_core(message: &[u8], bits: usize) -> Result<Vec<u8>, PyErr> {
    if bits != 256 && bits != 512 {
        return Err(PyValueError::new_err("streebog bits must be 256 or 512"));
    }
    let mut h = if bits == 512 {
        [0u8; 64]
    } else {
        [0x01u8; 64] // practical 256-bit IV
    };
    let mut n = [0u8; 64];
    let mut sigma = [0u8; 64];
    let mut msg = message;
    while msg.len() >= 64 {
        let block: [u8; 64] = msg[..64].try_into().unwrap(); // FIRST block first
        msg = &msg[64..];
        h = bswap64(&g(&bswap64(&h), &bswap64(&n), &bswap64(&block)));
        n = add512_le(&n, &{
            let mut v = [0u8; 64];
            v[..8].copy_from_slice(&512u64.to_le_bytes());
            v
        });
        sigma = add512_le(&sigma, &block);
    }
    let rem = msg.len();
    let mut pad = [0u8; 64];
    pad[..rem].copy_from_slice(msg);
    pad[rem] = 0x01; // padding FOLLOWS the message
    h = bswap64(&g(&bswap64(&h), &bswap64(&n), &bswap64(&pad)));
    {
        let mut v = [0u8; 64];
        v[..8].copy_from_slice(&((rem * 8) as u64).to_le_bytes());
        n = add512_le(&n, &v);
    }
    sigma = add512_le(&sigma, &pad);
    h = bswap64(&g(&bswap64(&h), &[0u8; 64], &bswap64(&n)));
    h = bswap64(&g(&bswap64(&h), &[0u8; 64], &bswap64(&sigma)));
    Ok(h[64 - bits / 8..].to_vec())
}

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
#[pyo3(signature = (message, bits=256))]
pub fn streebog(message: Vec<u8>, bits: usize) -> PyResult<Vec<u8>> {
    streebog_core(&message, bits)
}

#[pyfunction]
pub fn streebog_256(message: Vec<u8>) -> PyResult<Vec<u8>> {
    streebog_core(&message, 256)
}

#[pyfunction]
pub fn streebog_512(message: Vec<u8>) -> PyResult<Vec<u8>> {
    streebog_core(&message, 512)
}

#[pyfunction]
#[pyo3(signature = (message, bits=256))]
pub fn streebog_practical(message: Vec<u8>, bits: usize) -> PyResult<Vec<u8>> {
    streebog_practical_core(&message, bits)
}
