pub fn tree_fold<T, R, F, B>(a: &[T], f: &F, base: &B) -> R
where
    F: Fn(R, R) -> R,
    B: Fn(&T) -> R,
{
    assert!(!a.is_empty(), "empty slice in tree_fold");
    fn recur<T, R, F, B>(a: &[T], i0: usize, i1: usize, f: &F, base: &B) -> R
    where
        F: Fn(R, R) -> R,
        B: Fn(&T) -> R,
    {
        if i1 - i0 > 1 {
            let im = i0 + (i1 - i0) / 2;
            f(recur(a, i0, im, f, base), recur(a, im, i1, f, base))
        } else if i1 - i0 == 1 {
            base(&a[i0])
        } else {
            panic!("ill-formed indices in fold");
        }
    }
    recur(a, 0, a.len(), f, base)
}

pub fn tree_fold2<T1, T2, R, F, B>(a: &[T1], b: &[T2], f: &F, base: &B) -> R
where
    F: Fn(R, R) -> R,
    B: Fn(&T1, &T2) -> R,
{
    assert_eq!(a.len(), b.len(), "slice lengths mismatch in tree_fold2");
    assert!(!a.is_empty(), "empty slices in tree_fold2");
    fn recur<T1, T2, R, F, B>(a: &[T1], b: &[T2], i0: usize, i1: usize, f: &F, base: &B) -> R
    where
        F: Fn(R, R) -> R,
        B: Fn(&T1, &T2) -> R,
    {
        if i1 - i0 > 1 {
            let im = i0 + (i1 - i0) / 2;
            f(recur(a, b, i0, im, f, base), recur(a, b, im, i1, f, base))
        } else if i1 - i0 == 1 {
            base(&a[i0], &b[i0])
        } else {
            panic!("ill-formed indices in fold2");
        }
    }
    recur(a, b, 0, a.len(), f, base)
}

pub fn init<T, F>(n: usize, f: F) -> Vec<T>
where F: Fn(usize) -> T {
    (0..n).map(f).collect()
}

pub fn map<T, R, F>(a: &[T], f: F) -> Vec<R>
where F: Fn(&T) -> R {
    a.iter().map(f).collect()
}

pub fn map2<T1, T2, R, F>(a: &[T1], b: &[T2], f: F) -> Vec<R>
where F: Fn(&T1, &T2) -> R {
    assert_eq!(a.len(), b.len(), "slice lengths mismatch in map2");
    (0..a.len()).map(|i| f(&a[i], &b[i])).collect()
}

pub fn map3<T1, T2, T3, R, F>(a: &[T1], b: &[T2], c: &[T3], f: F) -> Vec<R>
where F: Fn(&T1, &T2, &T3) -> R {
    assert_eq!(a.len(), b.len(), "slice lengths mismatch in map3");
    assert_eq!(a.len(), c.len(), "slice lengths mismatch in map3");
    (0..a.len()).map(|i| f(&a[i], &b[i], &c[i])).collect()
}
