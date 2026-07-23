pub mod array;
pub mod memoize;
pub mod morton;

/// Computes the ceiling of the base-2 logarithm: ceil(log2(n)).
/// Panics if n == 0.
#[must_use]
pub fn ceil_log2(n: usize) -> usize {
    match n {
        0 => panic!("log2 of zero is undefined"),
        1 => 0,
        _ => (n - 1).ilog2() as usize + 1,
    }
}
