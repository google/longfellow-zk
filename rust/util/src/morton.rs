/// Extracts even bits from x.
#[must_use]
pub fn even(mut x: u64) -> u64 {
    x &= 0x5555_5555_5555_5555;
    x |= x >> 1;
    x &= 0x3333_3333_3333_3333;
    x |= x >> 2;
    x &= 0x0F0F_0F0F_0F0F_0F0F;
    x |= x >> 4;
    x &= 0x00FF_00FF_00FF_00FF;
    x |= x >> 8;
    x &= 0x0000_FFFF_0000_FFFF;
    x |= x >> 16;
    x &= 0x0000_0000_FFFF_FFFF;
    x
}

/// Spreads bits of x into even positions (inverse of even).
#[must_use]
pub fn uneven(mut x: u64) -> u64 {
    x &= 0x0000_0000_FFFF_FFFF;
    x |= x << 16;
    x &= 0x0000_FFFF_0000_FFFF;
    x |= x << 8;
    x &= 0x00FF_00FF_00FF_00FF;
    x |= x << 4;
    x &= 0x0F0F_0F0F_0F0F_0F0F;
    x |= x << 2;
    x &= 0x3333_3333_3333_3333;
    x |= x << 1;
    x &= 0x5555_5555_5555_5555;
    x
}

#[must_use]
pub fn cmp(x0: usize, x1: usize, y0: usize, y1: usize) -> std::cmp::Ordering {
    let diff0 = x0 ^ y0;
    let diff1 = x1 ^ y1;
    if diff0 == 0 && diff1 == 0 {
        return std::cmp::Ordering::Equal;
    }
    if diff1 == 0 {
        let msb0 = (usize::BITS - 1) - diff0.leading_zeros();
        if ((x0 >> msb0) & 1) == 0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    } else if diff0 == 0 {
        let msb1 = (usize::BITS - 1) - diff1.leading_zeros();
        if ((x1 >> msb1) & 1) == 0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    } else {
        let msb0 = (usize::BITS - 1) - diff0.leading_zeros();
        let msb1 = (usize::BITS - 1) - diff1.leading_zeros();
        let is_less = if msb1 >= msb0 {
            ((x1 >> msb1) & 1) == 0
        } else {
            ((x0 >> msb0) & 1) == 0
        };
        if is_less {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    }
}
