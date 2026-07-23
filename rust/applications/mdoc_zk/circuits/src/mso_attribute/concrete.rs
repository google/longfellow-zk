#[derive(Clone, Copy, Debug)]
pub struct FieldLocator {
    pub slot_position: [usize; 4],
    pub length: [usize; 4],
    pub permutation: usize,
}

#[derive(Clone, Debug)]
pub struct DisclosedAttribute {
    pub expected_name: Vec<u8>,
    pub expected_cbor_value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConcreteGiven {
    pub name: Vec<u8>,
    pub cbor_value: Vec<u8>,
    pub preimage: Vec<u8>,
    pub field_locator: FieldLocator,
    pub expected_digest: [u32; 8],
}

#[derive(Clone, Debug)]
pub struct ConcreteDerived {
    pub sha_derived: circuits_sha256msg::concrete::ConcreteDerived,
}

#[must_use]
pub fn derived(given: &ConcreteGiven) -> ConcreteDerived {
    ConcreteDerived {
        sha_derived: circuits_sha256msg::concrete::ConcreteDerived {
            sha_derived: circuits_sha256msg::concrete::sha256_msg_derived(
                &given.preimage,
                &circuits_sha256::constants::INITIAL,
                2,
            ),
        },
    }
}
