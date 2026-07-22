use super::Field;

pub fn axpy<F: Field>(y: &mut [F], x: &[F], a: F) {
    assert_eq!(y.len(), x.len(), "axpy dimension mismatch");
    for i in 0..y.len() {
        y[i] += a * x[i];
    }
}

pub fn vaxpy<F: Field>(y: &mut [F], x: &[F], a: &[F]) {
    assert_eq!(y.len(), x.len(), "vaxpy dimension mismatch (x/y)");
    assert_eq!(y.len(), a.len(), "vaxpy dimension mismatch (a/y)");
    for i in 0..y.len() {
        y[i] += a[i] * x[i];
    }
}

pub fn dot<F: Field>(a: &[F], b: &[F]) -> F {
    assert_eq!(a.len(), b.len(), "dot dimension mismatch");
    let mut sum = F::zero();
    for i in 0..a.len() {
        sum += a[i] * b[i];
    }
    sum
}

pub fn dot1<F: Field>(slice: &[F]) -> F {
    let mut sum = F::zero();
    for &x in slice {
        sum += x;
    }
    sum
}
