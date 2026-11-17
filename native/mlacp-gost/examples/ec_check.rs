// Cross-check: compute k*G for a given 512-bit k (LE hex on stdin line 2)
// and print the affine point as LE hex. Used to validate against Python.
use mlacp_gost_rs::ec;
use std::io::Read as _;
fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let mut lines = s.lines();
    let p = lines.next().unwrap();
    let a = lines.next().unwrap();
    let b = lines.next().unwrap();
    let k = lines.next().unwrap();
    let x = lines.next().unwrap();
    let y = lines.next().unwrap();
    let hx = |s: &str| {
        s.as_bytes()
            .chunks(2)
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>()
    };
    let (p, a, b, k, x, y) = (hx(p), hx(a), hx(b), hx(k), hx(x), hx(y));
    if !ec::point_on_curve(&p, &a, &b, &x, &y) {
        println!("ON_CURVE false");
        return;
    }
    match ec::scalar_mult(&p, &a, &k, &x, &y) {
        Some((rx, ry)) => {
            let h = |v: &Vec<u8>| v.iter().map(|c| format!("{:02x}", c)).collect::<String>();
            println!("ON_CURVE true");
            println!("X {}", h(&rx));
            println!("Y {}", h(&ry));
        }
        None => println!("ON_CURVE true\nINF"),
    }
}
