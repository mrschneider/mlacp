//! Constant-time (table-free) Kuznyechik S∘L, for hostile-co-tenancy threat
//! models. The default path is table-driven (fast, cache-timing dependent);
//! this one has NO secret-indexed memory access:
//!
//! - S via the ANF of each output bit (AND/XOR circuit over the 8 input
//!   bits; the monomial structure is public, evaluation is branchless);
//! - L as a 128x128 GF(2) matrix applied with native `count_ones` parity.
//!
//! The price is real: ~1000x slower than the tables. Use it when the threat
//! model demands it, not as the default.

use crate::sbox_anf::S_ANF;

/// Kuznyechik S-box without any table: evaluate the ANF of each output bit.
/// The monomial masks are public structure; every operation depends only on
/// them and on the byte, with no data-dependent branches or memory lookups.
pub fn s_ct(x: u8) -> u8 {
    let mut y = 0u8;
    for (bit, &monos) in S_ANF.iter().enumerate() {
        let mut acc = 0u8;
        for &m in monos {
            // product of the input bits selected by the monomial mask
            let mut p = 1u8;
            let mut mm = m;
            while mm != 0 {
                p &= (x >> mm.trailing_zeros()) & 1; // lowest set bit's index
                mm &= mm - 1;
            }
            acc ^= p;
        }
        y |= acc << bit;
    }
    y
}

/// The L transform as a 128x128 GF(2) matrix: L_ROW[i] has bit p set iff
/// input bit p contributes to output bit i. parity(L_ROW[i] & x) via
/// `count_ones` is constant-time on modern hardware.
fn l_rows() -> &'static [u128; 128] {
    static ROWS: std::sync::OnceLock<[u128; 128]> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        let mut rows = [0u128; 128];
        for p in 0..128usize {
            // basis vector e_p in BIG-ENDIAN u128 convention: bit p of the
            // integer is byte (15 - p/8), bit p%8 — the same mapping both
            // `from_be_bytes` and `to_be_bytes` use, so rows stay consistent
            let mut a = [0u8; 16];
            a[15 - p / 8] = 1 << (p % 8);
            let out = crate::l_lin(&a);
            for i in 0..128usize {
                let bit = (out[15 - i / 8] >> (i % 8)) & 1;
                rows[i] |= (bit as u128) << p;
            }
        }
        rows
    })
}

pub fn l_ct(x: &[u8; 16]) -> [u8; 16] {
    let v = u128::from_be_bytes(*x);
    let rows = l_rows();
    let mut out = 0u128;
    for (i, row) in rows.iter().enumerate() {
        let par = ((row & v).count_ones() & 1) as u128;
        out |= par << i;
    }
    out.to_be_bytes()
}

/// Constant-time LSX(k, a) = L(S(k ⊕ a)).
pub fn lsx_ct(k: &[u8; 16], a: &[u8; 16]) -> [u8; 16] {
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = s_ct(k[i] ^ a[i]);
    }
    l_ct(&t)
}
