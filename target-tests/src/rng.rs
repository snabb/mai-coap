// Deliberately predictable: emulated test fixtures must never establish production keys.
pub(crate) struct TestRng(pub(crate) u64);
impl rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        Ok(self.0 as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok((u64::from(self.try_next_u32()?) << 32) | u64::from(self.try_next_u32()?))
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in output.chunks_mut(4) {
            chunk.copy_from_slice(&self.try_next_u32()?.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for TestRng {}
