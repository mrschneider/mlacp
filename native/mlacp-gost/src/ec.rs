//! Native VKO elliptic-curve arithmetic (GOST R 34.10-2012 curves).
//!
//! Prime field in Montgomery form over w u64 limbs (w = 4 for the 256-bit
//! curves, w = 8 for the 512-bit curves) — no external dependencies, no
//! u32-digit Knuth division. Jacobian projective double-and-add with an
//! 8-bit window: ~bit_length doublings + ~bit_length/8 additions + ONE
//! field inverse (the final Jacobian -> affine conversion), exactly the
//! operation sequence of the pure-Python reference
//! (mlacp_core/gost_ec.py). Coordinates cross the FFI as little-endian
//! byte strings (the ГОСТ wire convention), so the public keys and the
//! RFC 7836 vectors are unchanged by this backend.
//!
//! The pure-Python implementation remains the readable reference and the
//! fallback when the native module is absent (MLACP_PURE=1 forces it).

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// All field elements are stored as 8-limb arrays; a w-limb field uses the
// low w limbs (the rest are zero). This keeps the Point struct monomorphic.
type E = [u64; 8];

// ---------------------------------------------------------------------------
// Field arithmetic (Montgomery, generic width)
// ---------------------------------------------------------------------------

/// Montgomery reduction: t (2w limbs) -> t * R^{-1} mod p, R = 2^(64w).
/// CIOS Montgomery reduction: t (2w limbs) -> t * R^{-1} mod p, R = 2^(64w).
///
/// CRITICAL for full 512-bit primes (GOST 512: p < 2^512 but 2p > 2^512):
/// the true reduced value is < 2p < 2^513, so it can overflow the 2w-limb
/// accumulator by ONE bit. We track that dropped top carry and add it back:
/// a dropped unit at bit 64w is worth 2^(64w) ≡ (2^(64w) - p) (mod p), and
/// 2^(64w) - p is tiny (569 for GOST 512). The result then lies in
/// [0, 2p), so up to TWO conditional subtractions bring it to [0, p).
#[inline]
fn fp_reduce_w(t: &mut [u64; 16], w: usize, p: &E, n0: u64) -> E {
    let mut top_carry: u64 = 0;
    for i in 0..w {
        let m = t[i].wrapping_mul(n0);
        let mut carry: u128 = 0;
        for j in 0..w {
            let v = t[i + j] as u128 + m as u128 * p[j] as u128 + carry;
            t[i + j] = v as u64;
            carry = v >> 64;
        }
        let mut ci = i + w;
        while carry != 0 {
            if ci < 2 * w {
                let v = t[ci] as u128 + carry;
                t[ci] = v as u64;
                carry = v >> 64;
            } else {
                top_carry += carry as u64; // 0 or 1 in practice
                carry = 0;
            }
            ci += 1;
        }
    }
    let mut out = [0u64; 8];
    out[..w].copy_from_slice(&t[w..2 * w]);
    if top_carry != 0 {
        // Add top_carry * (2^(64w) - p); d = 2^(64w) - p = ~p + 1 (the
        // two's complement of p). No final carry: out < 2p and d < 2^64.
        let mut d = [0u64; 8];
        let mut carry: u64 = 1; // the +1 in ~p + 1
        for i in 0..w {
            let (v, c1) = (!p[i]).overflowing_add(carry);
            d[i] = v;
            carry = c1 as u64;
        }
        let mut c: u128 = 0;
        for i in 0..w {
            let v = out[i] as u128 + d[i] as u128 * top_carry as u128 + c;
            out[i] = v as u64;
            c = v >> 64;
        }
    }
    // out < 2p, so up to TWO conditional subtractions.
    if ge_w(&out, w, p) {
        sub_w(&mut out, w, p);
    }
    if ge_w(&out, w, p) {
        sub_w(&mut out, w, p);
    }
    out
}

/// Schoolbook w x w -> 2w-limb product.
#[inline]
fn fp_product_w(a: &E, b: &E, w: usize) -> [u64; 16] {
    let mut t = [0u64; 16];
    for i in 0..w {
        let mut carry: u128 = 0;
        for j in 0..w {
            let v = t[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
            t[i + j] = v as u64;
            carry = v >> 64;
        }
        // Propagate the row carry through ALL upper limbs: t[i+w] may
        // overflow (the row partial sum can be up to ~2*p + 2^64-1 for
        // a near-modulus product), so a single wrapping_add loses bits.
        let mut ci = i + w;
        while carry != 0 && ci < 2 * w {
            let v = t[ci] as u128 + carry;
            t[ci] = v as u64;
            carry = v >> 64;
            ci += 1;
        }
    }
    t
}

#[inline]
fn mul_w(f: &Fp, a: &E, b: &E) -> E {
    let mut t = fp_product_w(a, b, f.w);
    fp_reduce_w(&mut t, f.w, &f.p, f.n0)
}

#[inline]
fn sq_w(f: &Fp, a: &E) -> E {
    mul_w(f, a, a)
}

#[inline]
fn add_w(a: &E, b: &E, w: usize, p: &E, r_raw: &E) -> E {
    // a, b in [0, p): a+b < 2p < 2^(64w) + p, so at most ONE carry out of
    // the w limbs. With r = (a+b) mod 2^(64w), the field result is
    //   no carry:  a+b (already < 2p, so subtract p once if needed)
    //   carry:     a+b - 2^(64w) - p = r + R - p   (2^(64w) = p + R)
    // i.e. add r_raw = R (raw) when there was a carry, then ONE
    // conditional subtract of p.
    let mut r = [0u64; 8];
    let mut carry = 0u64;
    for i in 0..w {
        let (lo, c1) = a[i].overflowing_add(b[i]);
        let (lo2, c2) = lo.overflowing_add(carry);
        r[i] = lo2;
        carry = c1 as u64 + c2 as u64;
    }
    if carry != 0 {
        let mut c2 = 0u64;
        for i in 0..w {
            let (lo, c1) = r[i].overflowing_add(r_raw[i]);
            let (lo2, c) = lo.overflowing_add(c2);
            r[i] = lo2;
            c2 = c1 as u64 + c as u64;
        }
        // c2 may be 1 (then r is already canonical: r0-p with r0 >= p);
        // the ge_w check below handles both cases.
        let _ = c2;
    }
    if ge_w(&r, w, p) {
        sub_w(&mut r, w, p);
    }
    r
}

#[inline]
fn sub_w(a: &mut E, w: usize, b: &E) {
    let mut borrow = 0u64;
    for i in 0..w {
        let (lo, b1) = a[i].overflowing_sub(b[i]);
        let (lo2, b2) = lo.overflowing_sub(borrow);
        a[i] = lo2;
        borrow = b1 as u64 + b2 as u64;
    }
}

#[inline]
fn submod_w(a: &E, b: &E, w: usize, r_raw: &E) -> E {
    // a, b in [0, p). If a >= b: exact. If a < b: r = a-b+2^(64w) (wrapped)
    // and the field result is a-b+p. With 2^(64w) = p + R, we have
    // r = a-b+p+R, so the result is r - R, i.e. SUBTRACT r_raw = R.
    // (Earlier this ADDed R, giving a-b+p+2R — off by the Montgomery
    // representation of 2 — which corrupted every subtraction that wrapped,
    // e.g. X3 = M2 - 2S in a doubling where M2 < 2S.) r - R >= 1, so the
    // result lands in [1, p-1] with no underflow and no conditional.
    let mut r = [0u64; 8];
    let mut borrow = 0u64;
    for i in 0..w {
        let (lo, b1) = a[i].overflowing_sub(b[i]);
        let (lo2, b2) = lo.overflowing_sub(borrow);
        r[i] = lo2;
        borrow = b1 as u64 + b2 as u64;
    }
    if borrow != 0 {
        let mut borrow2 = 0u64;
        for i in 0..w {
            let (lo, b1) = r[i].overflowing_sub(r_raw[i]);
            let (lo2, b2) = lo.overflowing_sub(borrow2);
            r[i] = lo2;
            borrow2 = b1 as u64 + b2 as u64;
        }
        debug_assert_eq!(borrow2, 0);
    }
    r
}

#[inline]
fn ge_w(a: &E, w: usize, b: &E) -> bool {
    // a >= b. The equality case matters: Montgomery reduction leaves the
    // result in [0, 2p) and it CAN be exactly p (which must become 0);
    // a strict comparison silently kept p (== the Montgomery identity),
    // corrupting ~half of all multiplications.
    let mut g = false;
    let mut e = true;
    for i in (0..w).rev() {
        if a[i] > b[i] {
            g = true;
            e = false;
            break;
        }
        if a[i] < b[i] {
            e = false;
        }
    }
    g || e
}

#[inline]
fn eq_w(a: &E, b: &E, w: usize) -> bool {
    a[..w] == b[..w]
}

#[derive(Clone, Copy)]
struct Fp {
    w: usize,
    p: E,
    n0: u64,
    one: E, // R mod p (the Montgomery identity)
    r2: E,  // R^2 mod p (RAW — the to_mont multiplier)
    a: E,   // curve parameter a, in Montgomery form
    two: E,
    three: E,
    four: E,
    eight: E,
}

impl Fp {
    fn new(w: usize, p: E, a_affine: &E) -> Self {
        debug_assert!(w == 4 || w == 8);
        // n0 = -p^{-1} mod 2^64 by Newton iteration (converges in 6
        // doublings from any odd seed; the final wrapping_neg flips it
        // from p^{-1} to -p^{-1}, which is what CIOS reduction needs).
        let mut ninv = 1u64;
        for _ in 0..6 {
            ninv = ninv.wrapping_mul(2u64.wrapping_sub(p[0].wrapping_mul(ninv)));
        }
        let n0 = ninv.wrapping_neg();
        // R = 2^(64w) mod p and R^2 = 2^(128w) mod p, both by repeated
        // doubling from 1 with one conditional subtract per step (a value
        // < p doubled stays < 2p). No division at setup. R^2 (RAW, NOT
        // Montgomery-reduced) is the to_mont multiplier: v -> REDC(v*R^2)
        // = v*R mod p. (Applying REDC to R*R would give R, not R^2 — a
        // classic off-by-one-radix trap that makes to_mont a no-op.)
        fn pow2_mod(p: &E, w: usize, k: u32) -> E {
            let mut acc = [0u64; 9];
            acc[0] = 1;
            for _ in 0..k {
                let mut carry = 0u64;
                for limb in &mut acc[..8] {
                    let v = (*limb << 1) | carry;
                    carry = *limb >> 63;
                    *limb = v;
                }
                // The carry OUT of the top limb is the overflow flag: the
                // loop above only feeds it into the next limb, so it must be
                // captured explicitly. Without this, values >= 2^(64w) were
                // never reduced (one ended up as 2^(64w) mod 2^(64w)+garbage
                // = 0x...239, and the first to_mont call looked like a hang).
                acc[8] = carry;
                let mut ge = false;
                for i in (0..w).rev() {
                    if acc[i] != p[i] {
                        ge = acc[i] > p[i];
                        break;
                    }
                }
                if acc[8] != 0 || ge {
                    let mut borrow = 0u64;
                    for i in 0..w {
                        let (lo, b1) = acc[i].overflowing_sub(p[i]);
                        let (lo2, b2) = lo.overflowing_sub(borrow);
                        acc[i] = lo2;
                        borrow = b1 as u64 + b2 as u64;
                    }
                    acc[w] -= borrow;
                }
            }
            let mut out = [0u64; 8];
            out[..w].copy_from_slice(&acc[..w]);
            out
        }
        let one = pow2_mod(&p, w, 64 * w as u32);
        let r2 = pow2_mod(&p, w, 128 * w as u32);
        let to_mont = |v: &E| {
            let mut t = fp_product_w(v, &r2, w);
            fp_reduce_w(&mut t, w, &p, n0)
        };
        let c2 = {
            let mut v = [0u64; 8];
            v[0] = 2;
            v
        };
        let c3 = {
            let mut v = [0u64; 8];
            v[0] = 3;
            v
        };
        let c4 = {
            let mut v = [0u64; 8];
            v[0] = 4;
            v
        };
        let c8 = {
            let mut v = [0u64; 8];
            v[0] = 8;
            v
        };
        Fp {
            w,
            a: to_mont(a_affine),
            one,
            r2,
            two: to_mont(&c2),
            three: to_mont(&c3),
            four: to_mont(&c4),
            eight: to_mont(&c8),
            n0,
            p,
        }
    }

    // "from_mont" is the standard name for the radix conversion even
    // though it needs the field (R^{-1} lives in `self`).
    #[allow(clippy::wrong_self_convention)]
    fn from_mont(self, a: &E) -> E {
        let one = [1u64, 0, 0, 0, 0, 0, 0, 0];
        mul_w(&self, a, &one)
    }

    /// into Montgomery form: a * R mod p  (= Montgomery-reduce a * R^2).
    fn to_mont(self, a: &E) -> E {
        let mut t = fp_product_w(a, &self.r2, self.w);
        fp_reduce_w(&mut t, self.w, &self.p, self.n0)
    }

    /// a^{-1} mod p by Fermat (a^{p-2}), a in MONTGOMERY form.
    ///
    /// Montgomery multiplication is homomorphic: MONT(aR, bR) = (ab)R, so
    /// exponentiating aR to the power p-2 yields a^{p-2}R = a^{-1}R — the
    /// inverse already in the correct (Montgomery) radix. No correction
    /// factor is needed (unlike a naive "multiply by R^2" which would give
    /// a^{-1}R^3).
    fn inv(&self, a: &E) -> E {
        let mut exp = self.p;
        // p - 2 in RAW form (self.two is Montgomery form — do NOT use it)
        let mut two_raw = [0u64; 8];
        two_raw[0] = 2;
        sub_w(&mut exp, self.w, &two_raw);
        let mut result = self.one;
        let mut base = *a;
        for limb in exp.iter().take(self.w) {
            let mut e = *limb;
            for _ in 0..64 {
                if e & 1 != 0 {
                    result = mul_w(self, &result, &base);
                }
                base = sq_w(self, &base);
                e >>= 1;
            }
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Jacobian projective point arithmetic (short Weierstrass)
// Point at infinity: z == 0 (canonical form (1, 1, 0)).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Pt {
    x: E,
    y: E,
    z: E,
}

impl Pt {
    fn infinity() -> Self {
        Pt {
            x: [1, 0, 0, 0, 0, 0, 0, 0],
            y: [1, 0, 0, 0, 0, 0, 0, 0],
            z: [0; 8],
        }
    }
    fn is_infinity(&self) -> bool {
        self.z == [0; 8]
    }
}

/// 2·P in Jacobian form. 8 multiplications.
fn jdouble(f: &Fp, P: &Pt) -> Pt {
    if P.is_infinity() {
        return Pt::infinity();
    }
    if eq_w(&P.y, &[0; 8], f.w) {
        // order-2 point (y == 0): its double is the point at infinity
        return Pt::infinity();
    }
    let Y1sq = sq_w(f, &P.y);
    let XY = mul_w(f, &P.x, &Y1sq);
    let S = mul_w(f, &f.four, &XY); // 4·X1·Y1²
    let Z1sq = sq_w(f, &P.z);
    let Z14 = sq_w(f, &Z1sq);
    let x3 = sq_w(f, &P.x);
    let M3 = mul_w(f, &f.three, &x3);
    let aZ = mul_w(f, &f.a, &Z14);
    let M = add_w(&M3, &aZ, f.w, &f.p, &f.one); // 3X1² + a·Z1⁴
    let M2 = sq_w(f, &M);
    let twoS = mul_w(f, &f.two, &S);
    let X3 = submod_w(&M2, &twoS, f.w, &f.one); // M² − 2S
    let YZ = mul_w(f, &P.y, &P.z);
    let Z3 = mul_w(f, &f.two, &YZ); // 2·Y1·Z1
    let SX = submod_w(&S, &X3, f.w, &f.one);
    let MSX = mul_w(f, &M, &SX);
    let Y14 = sq_w(f, &Y1sq);
    let e8 = mul_w(f, &f.eight, &Y14);
    let Y3 = submod_w(&MSX, &e8, f.w, &f.one); // M(S−X3) − 8·Y1⁴
    Pt {
        x: X3,
        y: Y3,
        z: Z3,
    }
}

/// Mixed addition: Q is AFFINE (z = 1). Correct for P == Q (reduces to a
/// double). P at infinity is a guard, not a formula case.
fn jadd_mixed(f: &Fp, P: &Pt, x2: &E, y2: &E) -> Pt {
    if P.is_infinity() {
        return Pt {
            x: *x2,
            y: *y2,
            z: f.one,
        };
    }
    let Z1sq = sq_w(f, &P.z);
    let Z1cu = mul_w(f, &Z1sq, &P.z);
    let U1 = P.x;
    let U2 = mul_w(f, x2, &Z1sq);
    let S1 = P.y;
    let S2 = mul_w(f, y2, &Z1cu);
    if eq_w(&U1, &U2, f.w) {
        return if eq_w(&S1, &S2, f.w) {
            jdouble(f, P)
        } else {
            Pt::infinity()
        };
    }
    let H = submod_w(&U2, &U1, f.w, &f.one);
    let R = submod_w(&S2, &S1, f.w, &f.one);
    let Hsq = sq_w(f, &H);
    let Hcu = mul_w(f, &H, &Hsq);
    let U1Hsq = mul_w(f, &U1, &Hsq);
    let twoU1Hsq = mul_w(f, &f.two, &U1Hsq);
    let R2 = sq_w(f, &R);
    let X3 = submod_w(&submod_w(&R2, &Hcu, f.w, &f.one), &twoU1Hsq, f.w, &f.one);
    let Z3 = mul_w(f, &H, &P.z);
    let S1Hcu = mul_w(f, &S1, &Hcu);
    let Y3 = submod_w(
        &mul_w(f, &R, &submod_w(&U1Hsq, &X3, f.w, &f.one)),
        &S1Hcu,
        f.w,
        &f.one,
    );
    Pt {
        x: X3,
        y: Y3,
        z: Z3,
    }
}

/// General Jacobian addition: BOTH P and Q are Jacobian (no inverse).
fn jadd_jac(f: &Fp, P: &Pt, Q: &Pt) -> Pt {
    if P.is_infinity() {
        return *Q;
    }
    if Q.is_infinity() {
        return *P;
    }
    let Z1sq = sq_w(f, &P.z);
    let Z2sq = sq_w(f, &Q.z);
    let U1 = mul_w(f, &P.x, &Z2sq);
    let U2 = mul_w(f, &Q.x, &Z1sq);
    let Z2q = mul_w(f, &Z2sq, &Q.z);
    let S1 = mul_w(f, &P.y, &Z2q);
    let Z1p = mul_w(f, &Z1sq, &P.z);
    let S2 = mul_w(f, &Q.y, &Z1p);
    if eq_w(&U1, &U2, f.w) {
        return if eq_w(&S1, &S2, f.w) {
            jdouble(f, P)
        } else {
            Pt::infinity()
        };
    }
    let H = submod_w(&U2, &U1, f.w, &f.one);
    let R = submod_w(&S2, &S1, f.w, &f.one);
    let Hsq = sq_w(f, &H);
    let Hcu = mul_w(f, &H, &Hsq);
    let V = mul_w(f, &U1, &Hsq);
    let R2 = sq_w(f, &R);
    let twoV = mul_w(f, &f.two, &V);
    let X3 = submod_w(&submod_w(&R2, &Hcu, f.w, &f.one), &twoV, f.w, &f.one);
    let PZ = mul_w(f, &P.z, &Q.z);
    let Z3 = mul_w(f, &H, &PZ);
    let S1Hcu = mul_w(f, &S1, &Hcu);
    let Y3 = submod_w(
        &mul_w(f, &R, &submod_w(&V, &X3, f.w, &f.one)),
        &S1Hcu,
        f.w,
        &f.one,
    );
    Pt {
        x: X3,
        y: Y3,
        z: Z3,
    }
}

fn to_affine(f: &Fp, P: &Pt) -> Option<(E, E)> {
    if P.is_infinity() {
        return None;
    }
    let Zinv = f.inv(&P.z);
    let Zinv2 = sq_w(f, &Zinv);
    let x = f.from_mont(&mul_w(f, &P.x, &Zinv2));
    let Zy = mul_w(f, &Zinv2, &Zinv);
    let y = f.from_mont(&mul_w(f, &P.y, &Zy));
    Some((x, y))
}

/// y² == x³ + a·x + b in the field (x, y given RAW, little-endian).
pub fn point_on_curve(p: &[u8], a: &[u8], b: &[u8], x: &[u8], y: &[u8]) -> bool {
    let w = p.len() / 8;
    if w != 4 && w != 8 {
        return false;
    }
    let p_l = bytes_to_limbs(p);
    let a_l = bytes_to_limbs(a);
    let b_l = bytes_to_limbs(b);
    let fp = Fp::new(w, p_l, &a_l);
    let x_l = fp.to_mont(&bytes_to_limbs(x));
    let y_l = fp.to_mont(&bytes_to_limbs(y));
    let b_l = fp.to_mont(&b_l);
    let y2 = sq_w(&fp, &y_l);
    let x2 = sq_w(&fp, &x_l);
    let x3 = mul_w(&fp, &x2, &x_l);
    let ax = mul_w(&fp, &fp.a, &x_l);
    let rhs = add_w(&add_w(&x3, &ax, w, &fp.p, &fp.one), &b_l, w, &fp.p, &fp.one);
    eq_w(&y2, &rhs, w)
}

// ---------------------------------------------------------------------------
// Windowed scalar multiplication + per-point table cache
// ---------------------------------------------------------------------------

fn bytes_to_limbs(b: &[u8]) -> E {
    let mut out = [0u64; 8];
    for (i, chunk) in b.chunks(8).enumerate().take(8) {
        let mut v = 0u64;
        for (j, &byte) in chunk.iter().enumerate() {
            v |= (byte as u64) << (8 * j);
        }
        out[i] = v;
    }
    out
}

struct CurveCache {
    fp: Fp,
    // bounded per-point 8-bit window tables: key = affine (x, y) in
    // Montgomery form (canonical for the field, byte-length independent)
    tables: HashMap<(E, E), Vec<Pt>>,
}

static CURVES: OnceLock<Mutex<HashMap<(E, E), CurveCache>>> = OnceLock::new();

fn curve_cache() -> &'static Mutex<HashMap<(E, E), CurveCache>> {
    CURVES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 8-bit window table for an AFFINE point: tab[i] = (i+1)·P, Jacobian
/// (built by mixed adds, zero inverses). Bounded to 16 entries per curve:
/// a peer's public key is reused across messages, random points are not.
fn window_table(c: &mut CurveCache, x: &E, y: &E) -> Vec<Pt> {
    let key = (*x, *y);
    if let Some(tab) = c.tables.get(&key) {
        return tab.clone();
    }
    let mut tab = vec![Pt {
        x: *x,
        y: *y,
        z: c.fp.one,
    }];
    let mut cur = tab[0];
    for _ in 0..255 {
        cur = jadd_mixed(&c.fp, &cur, x, y);
        tab.push(cur);
    }
    if c.tables.len() >= 16 {
        // bounded: drop any oldest entry (rebuilt on demand)
        if let Some(old) = c.tables.keys().next().copied() {
            c.tables.remove(&old);
        }
    }
    c.tables.insert(key, tab.clone());
    tab
}

/// k·P with P = (x, y) affine; the caller handles scalar reduction (the
/// subgroup check needs the unreduced q — the Python layer passes it
/// through). All byte strings are little-endian. Returns None for the
/// point at infinity.
pub fn scalar_mult(p: &[u8], a: &[u8], k: &[u8], x: &[u8], y: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let w = p.len() / 8;
    if w != 4 && w != 8 {
        return None;
    }
    let p_l = bytes_to_limbs(p);
    let a_l = bytes_to_limbs(a);
    let mut guard = curve_cache().lock().unwrap();
    let c = guard.entry((p_l, a_l)).or_insert_with(|| CurveCache {
        fp: Fp::new(w, p_l, &a_l),
        tables: HashMap::new(),
    });
    // point coordinates enter in MONTGOMERY form: every field operation
    // (window table, doubling, adds) is in Montgomery form, and the
    // final affine conversion is a single from_mont per coordinate.
    let x_l = c.fp.to_mont(&bytes_to_limbs(x));
    let y_l = c.fp.to_mont(&bytes_to_limbs(y));
    let mut k_l = [0u64; 16];
    for (i, chunk) in k.chunks(8).enumerate().take(16) {
        let mut v = 0u64;
        for (j, &byte) in chunk.iter().enumerate() {
            v |= (byte as u64) << (8 * j);
        }
        k_l[i] = v;
    }
    if k_l.iter().all(|&v| v == 0) {
        return None;
    }
    let bitlen = (0..1024)
        .rev()
        .find(|&i| (k_l[i / 64] >> (i % 64)) & 1 != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    let nwin = bitlen.div_ceil(8);
    let tab = window_table(c, &x_l, &y_l);
    let fp = c.fp; // Copy of the immutable field constants
                   // Release the global lock before the heavy work: everything we need is
                   // now owned (fp is a Copy, tab a clone), so no other thread is blocked
                   // while we multiply.
    drop(guard);
    let mut r = Pt::infinity();
    // MSB-first, windowed: the FIRST (most significant) window contains
    // the MSB, so NO doubling precedes it; every later window is preceded
    // by 8 doublings. (Doubling 8 times before the top window would
    // compute 2^8·(top window) — e.g. 66·G instead of 2·G for k = 0b10.)
    for wwin in (0..nwin).rev() {
        let bits = if wwin == nwin - 1 { 0 } else { 8 };
        for _ in 0..bits {
            r = jdouble(&fp, &r);
        }
        let mut nib: u64 = 0;
        for b in 0..8 {
            nib |= ((k_l[(8 * wwin + b) / 64] >> ((8 * wwin + b) % 64)) & 1) << b;
        }
        if nib != 0 {
            r = jadd_jac(&fp, &r, &tab[(nib - 1) as usize]);
        }
    }
    to_affine(&fp, &r).map(|(xa, ya)| {
        (
            xa[..w].iter().flat_map(|l| l.to_le_bytes()).collect(),
            ya[..w].iter().flat_map(|l| l.to_le_bytes()).collect(),
        )
    })
}

#[cfg(test)]
mod ec_tests {
    use super::*;
    use std::time::Instant;

    fn hx(e: &E) -> String {
        e[..8].iter().rev().map(|l| format!("{:016x}", l)).collect()
    }

    #[test]
    fn inv_check() {
        let p = "00".to_string() + &"FF".repeat(62) + "FDC7";
        let a = "00".to_string() + &"FF".repeat(62) + "FDC4";
        let pl = bytes_to_limbs(&hex_le(&p));
        let al = bytes_to_limbs(&hex_le(&a));
        let fp = Fp::new(8, pl, &al);
        // inv(2R) * (2R) must be the Montgomery identity R
        let two_mont = fp.to_mont(&[2u64, 0, 0, 0, 0, 0, 0, 0]);
        let prod = mul_w(&fp, &two_mont, &fp.inv(&two_mont));
        assert!(
            eq_w(&prod, &fp.one, 8),
            "2*inv(2) != 1: prod={} one={}",
            hx(&prod),
            hx(&fp.one)
        );
        // inv(one) == one
        assert!(eq_w(&fp.inv(&fp.one), &fp.one, 8), "inv(1) != 1");
        // 3 * inv(3) == 1
        let three_mont = fp.to_mont(&[3u64, 0, 0, 0, 0, 0, 0, 0]);
        assert!(
            eq_w(&mul_w(&fp, &three_mont, &fp.inv(&three_mont)), &fp.one, 8),
            "3*inv(3) != 1"
        );
    }

    /// Regression test for the full-512-bit-prime CIOS top-carry fix:
    /// (2p > 2^512, so the reduction result can overflow the 512-bit
    /// accumulator). Exercises full-range products (the ones that used to
    /// silently drop the bit 512 carry, giving results off by 2^512 - p
    /// = 569). Verified against the Python oracle over 30000 random
    /// values.
    #[test]
    fn field_arith_random() {
        let (p, a) = curve512();
        let pl = bytes_to_limbs(&hex_le(&p));
        let al = bytes_to_limbs(&hex_le(&a));
        let fp = Fp::new(8, pl, &al);
        // deterministic PRNG (xorshift64)
        let mut s: u64 = 0x9e3779b97f4a7c15;
        let mut rng = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for k in 0..200 {
            // two full-range field elements
            let mut av = [0u64; 8];
            let mut bv = [0u64; 8];
            for i in 0..8 {
                av[i] = rng();
                bv[i] = rng();
            }
            // force the high limb to be large (full-range stress)
            av[7] |= 0x8000000000000000;
            bv[7] |= 0x8000000000000000;
            let am = fp.to_mont(&av);
            let bm = fp.to_mont(&bv);
            let sq = sq_w(&fp, &am);
            let mul = mul_w(&fp, &am, &bm);
            // (a^2 + b^2) * inv(a^2 + b^2) == 1
            let sum = add_w(&sq, &mul, 8, &fp.p, &fp.one);
            let invsum = fp.inv(&sum);
            let prod = mul_w(&fp, &sum, &invsum);
            assert!(
                eq_w(&prod, &fp.one, 8),
                "k={}: sum*inv(sum) != 1: sum={} prod={} one={}",
                k,
                hx(&sum),
                hx(&prod),
                hx(&fp.one)
            );
            // a^2 * a == a^3 (associativity)
            let a2 = sq_w(&fp, &am);
            let a3a = mul_w(&fp, &a2, &am);
            let a3b = mul_w(&fp, &am, &a2);
            assert!(eq_w(&a3a, &a3b, 8), "k={}: a2*a != a*a2", k);
        }
    }

    /// big-endian hex string -> little-endian wire bytes
    fn hex_le(s: &str) -> Vec<u8> {
        let mut v = s
            .as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>();
        v.reverse();
        v
    }

    fn curve512() -> (String, String) {
        let p = "00".to_owned() + &"FF".repeat(62) + "FDC7";
        let a = "00".to_owned() + &"FF".repeat(62) + "FDC4";
        (p, a)
    }
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect()
    }

    /// Cross-check against the RFC 7836 Appendix A.1 key-3 test vector
    /// (independent of the pure-Python reference). This is the regression
    /// test for the submod_w sign bug: 2G's X3 = M2 - 2S wrapped (M2 < 2S),
    /// and the old "add R on borrow" produced an X off by exactly 2.
    #[test]
    fn test_scalar_mult_rfc7836_key3() {
        let (p, a) = curve512();
        let mut p = hex(&p);
        p.reverse();
        let mut a = hex(&a);
        a.reverse();
        let mut gy_le = hex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4");
        gy_le.reverse();
        // 48-byte big-endian scalar (RFC 7836 A.1 key-3) -> 64-byte
        // little-endian. Expected point verified by an independent
        // Python naive double-and-add on the same scalar.
        let kb = hex("10F4472B10C46E4017C21B8746991F69070108170A9830F82B940E28E5980004FB45291B9B2D71C38C911B0E0929E22A92012695B78F80059E130D8040A1");
        let mut k_le = kb;
        k_le.reverse();
        k_le.resize(64, 0);
        let r = scalar_mult(&p, &a, &k_le, &[3u8], &gy_le).unwrap();
        let rx = r.0.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let ry = r.1.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let exp_x = "444ba3cb490bc13136faf2fbdc1bfe917840c53040c77664ff5ab990dbc24f75c548b76fa405726e7d6a34e9ccd9cafbb3e237cb234afeea8091c9cee21a031f";
        let exp_y = "734979635a3499a8fe83556919600289308c83a0716a61f4fea5174df07f3fe5baf6c49be046ea0f363ff00362f039acadedc84a508c8eedc685eaf8348189ea";
        assert_eq!(rx, exp_x, "RFC 7836 A.1 key-3 X mismatch");
        assert_eq!(ry, exp_y, "RFC 7836 A.1 key-3 Y mismatch");
    }

    /// 2G and 3G must match independently-computed affine values (catches
    /// any doubling/addition regression; the pre-fix submod_w bug corrupted
    /// 2G's X coordinate by exactly 2).
    #[test]
    fn test_scalar_mult_small_k() {
        let (p, a) = curve512();
        let mut p = hex(&p);
        p.reverse();
        let mut a = hex(&a);
        a.reverse();
        let mut gy_le = hex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4");
        gy_le.reverse();
        let cases = [
            (2u8,
             "7c13ead2d9af82b91fb2fde18df45b37e4f2046a2a1d1516952a5d40cdbb34442f2b130a47b0f6e5a5583af45409b01df55cf1bf9d86a597ab962962fcdc893b",
             "51c0af917530fdb38bf1911fe0d754d864dffd373bed34751c5bd831c69d20ca923e9a8084b76fee70e683e1986e68146f7ada03794c7791a3a8e0e2e2c413c8"),
            (3u8,
             "c387cb7c6834e116844e5410bacf55ec7a9008b3572f4b765dd32d4d0b84d243a5fb88f4d5914217a1686109cc56b14df867a5b5dd3539b57e262a71b21affa1",
             "d6908d51ecd75c12c7b64f1a716f36c6d46d4ce92faccfea6ec1c4677eafd311b37e3f333f9e81a3bf4ff8d7483a1ec484b9b59b184f37307f63c47e41c4b53c"),
        ];
        for (k, exp_x, exp_y) in cases {
            let r = scalar_mult(&p, &a, &[k], &[3u8], &gy_le).unwrap();
            let rx = r.0.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            let ry = r.1.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            assert_eq!(rx, exp_x, "k={} X mismatch", k);
            assert_eq!(ry, exp_y, "k={} Y mismatch", k);
        }
    }

    /// 11G = 0b1011: two non-trivial windows (exercises the windowed
    /// MSB-first loop with a table lookup in the SECOND window, plus the
    /// jadd_jac path). Expected point verified by an independent Python
    /// naive double-and-add.
    #[test]
    fn test_scalar_mult_11g() {
        let (p, a) = curve512();
        let mut p = hex(&p);
        p.reverse();
        let mut a = hex(&a);
        a.reverse();
        let mut gy_le = hex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4");
        gy_le.reverse();
        let r = scalar_mult(&p, &a, &[11u8], &[3u8], &gy_le).unwrap();
        let rx = r.0.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let ry = r.1.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        let exp_x = "5b5c13e7e12ef0988071407414266905b510a18b1d0581eb274888a6949547ea0bedecdd0a240264476f0f972317549e01d3cc4725f6fa35fe64efb660f3cf62";
        let exp_y = "79cf4e55594038f76f73c6535748dde3b8d10c0306c91c8ae92176c811ca726e45dd058532922beec60024c9d52afb5403a2327d677d610cbcce5b5c40652c19";
        assert_eq!(rx, exp_x, "11G X mismatch");
        assert_eq!(ry, exp_y, "11G Y mismatch");
    }

    #[test]
    fn test_scalar_mult_k1() {
        let (p, a) = curve512();
        // scalar_mult takes WIRE (little-endian) byte strings
        let mut p = hex(&p);
        p.reverse();
        let mut a = hex(&a);
        a.reverse();
        let gx = vec![3u8];
        let mut gy_le = hex("7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4");
        gy_le.reverse();
        let k = vec![1u8];
        let t0 = Instant::now();
        let r = scalar_mult(&p, &a, &k, &gx, &gy_le);
        let dt = t0.elapsed();
        assert!(r.is_some(), "k=1 returned None");
        let (rx, ry) = r.unwrap();
        // outputs are full-width little-endian (64 bytes for 512-bit)
        let mut gx_le = vec![3u8];
        gx_le.resize(64, 0);
        assert_eq!(rx, gx_le, "x mismatch");
        assert_eq!(ry, gy_le, "y mismatch");
        println!("k=1 OK in {:?}", dt);
    }
}
