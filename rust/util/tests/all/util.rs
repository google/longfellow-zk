use util::ceil_log2;

#[test]
fn test_ceil_log2() {
    assert_eq!(ceil_log2(1), 0);
    assert_eq!(ceil_log2(2), 1);
    assert_eq!(ceil_log2(3), 2);
    assert_eq!(ceil_log2(4), 2);
    assert_eq!(ceil_log2(5), 3);
    assert_eq!(ceil_log2(8), 3);
    assert_eq!(ceil_log2(9), 4);
}

#[test]
#[should_panic(expected = "log2 of zero is undefined")]
fn test_ceil_log2_zero_panic() {
    let _ = ceil_log2(0);
}
