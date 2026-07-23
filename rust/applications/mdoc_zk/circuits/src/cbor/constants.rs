pub const K_COSE1_PREFIX: [u8; 18] = [
    0x84, 0x6A, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xA1, 0x01, 0x26,
    0x40, 0x59,
];
pub const K_COSE1_PREFIX_LEN: usize = 18;

pub const K_DEVICE_AUTHENTICATION_HEADER: [u8; 22] = [
    0x84, 0x74, b'D', b'e', b'v', b'i', b'c', b'e', b'A', b'u', b't', b'h', b'e', b'n', b't', b'i',
    b'c', b'a', b't', b'i', b'o', b'n',
];

pub const K_TAG32: [u8; 2] = [0x58, 0x20];

pub const K_COSE_SIGN1_SIGNING_HEADER: [u8; 17] = [
    0x84, 0x6A, b'S', b'i', b'g', b'n', b'a', b't', b'u', b'r', b'e', b'1', 0x43, 0xA1, 0x01, 0x26,
    0x40,
];

pub const K_TAG24: [u8; 2] = [0xD8, 0x18];
