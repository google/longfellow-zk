pub trait Rng {
    fn bytes(&mut self, len: usize) -> Vec<u8>;
}
