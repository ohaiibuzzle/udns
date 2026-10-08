// Only built for soft-float ARM (Entware armv7sf). There `f64::max` becomes a
// call to the C function `fmaximum_num`, which zig's bundled musl does not have,
// so the link fails. This is that function: the larger number, ignoring NaN.
// ponytail: drop this file once zig's musl ships fmaximum_num.

#[unsafe(no_mangle)]
pub extern "C" fn fmaximum_num(a: f64, b: f64) -> f64 {
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a > b {
        return a;
    }
    if b > a {
        return b;
    }
    // Equal values: only +0.0 vs -0.0 differ, and +0.0 counts as larger.
    if a.is_sign_positive() { a } else { b }
}
