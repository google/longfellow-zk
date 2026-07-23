#![allow(dead_code)]
use num_bigint::BigUint;

pub(crate) struct EcmulTestvec {
    pub exp: BigUint,
    pub ax: BigUint,
    pub ay: BigUint,
    pub bx: BigUint,
    pub by: BigUint,
}

pub(crate) fn get_testvec() -> EcmulTestvec {
    EcmulTestvec {
        exp: BigUint::parse_bytes(
            b"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
            16,
        )
        .unwrap(),
        ax: BigUint::parse_bytes(
            b"48439561293906451759052585252797914202762949526041747995844080717082404635286",
            10,
        )
        .unwrap(),
        ay: BigUint::parse_bytes(
            b"36134250956749795798585127919587881956611106672985015071877198253568414405109",
            10,
        )
        .unwrap(),
        bx: BigUint::parse_bytes(
            b"32164115044586727380168565265599487335087082516341636821340533322376231416140",
            10,
        )
        .unwrap(),
        by: BigUint::parse_bytes(
            b"100106127832852471698220364770054816539829212506848912556377224323407925454936",
            10,
        )
        .unwrap(),
    }
}
