//! Heap-free RustCrypto software provider (CRY-3–5).
use crate::{
    Error,
    crypto::{CryptoProvider, Sha256State},
};
use ccm::{
    Ccm,
    aead::{AeadInOut, KeyInit},
    consts::{U8, U13},
};
use p256::{PublicKey, SecretKey, elliptic_curve::sec1::ToSec1Point};
use sha2::{Digest, Sha256};

/// Software primitives using exactly one caller-supplied secure RNG.
/// Debug output deliberately excludes the RNG and all secret material (PLT-8).
pub struct SoftwareCrypto<R> {
    rng: R,
}
impl<R> core::fmt::Debug for SoftwareCrypto<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareCrypto").finish_non_exhaustive()
    }
}
impl<R> SoftwareCrypto<R> {
    /// Uses the application's secure RNG; the provider never obtains entropy implicitly.
    pub const fn new(rng: R) -> Self {
        Self { rng }
    }
}
/// Heap-free incremental SHA-256; buffered input is erased on drop.
/// Debug output excludes the hash state and buffered input.
pub struct SoftwareSha256(Sha256);
impl core::fmt::Debug for SoftwareSha256 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SoftwareSha256").finish_non_exhaustive()
    }
}
impl Sha256State for SoftwareSha256 {
    fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        self.0.update(input);
        Ok(())
    }
    fn finalize(self) -> Result<[u8; 32], Error> {
        Ok(self.0.finalize().into())
    }
}
impl<R: rand_core::CryptoRng> CryptoProvider for SoftwareCrypto<R> {
    type Sha256<'a>
        = SoftwareSha256
    where
        Self: 'a;
    fn sha256_start(&mut self) -> Result<Self::Sha256<'_>, Error> {
        Ok(SoftwareSha256(Sha256::new()))
    }
    fn hkdf_extract(&mut self, salt: Option<&[u8]>, input: &[u8]) -> Result<[u8; 32], Error> {
        Ok(hkdf::Hkdf::<Sha256>::extract(salt, input).0.into())
    }
    fn hkdf_expand(&mut self, prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), Error> {
        hkdf::Hkdf::<Sha256>::from_prk(prk)
            .map_err(|_| Error::Protection)?
            .expand(info, output)
            .map_err(|_| Error::Capacity)
    }
    fn encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; 8], Error> {
        let cipher = Ccm::<aes::Aes128, U8, U13>::new(key.into());
        Ok(cipher
            .encrypt_inout_detached(nonce.into(), aad, plaintext.into())
            .map_err(|_| Error::Protection)?
            .into())
    }
    fn decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), Error> {
        let cipher = Ccm::<aes::Aes128, U8, U13>::new(key.into());
        if cipher
            .decrypt_inout_detached(nonce.into(), aad, ciphertext.into(), tag.into())
            .is_err()
        {
            // OSC-9: unauthenticated plaintext must never reach a parser or handler.
            zeroize::Zeroize::zeroize(ciphertext);
            return Err(Error::Protection);
        }
        Ok(())
    }
    fn p256_key_pair(&mut self) -> Result<([u8; 32], [u8; 32]), Error> {
        for _ in 0..128 {
            let mut private = [0; 32];
            self.random(&mut private);
            if let Ok(secret) = SecretKey::from_slice(&private) {
                let point = secret.public_key().to_sec1_point(false);
                let mut x = [0; 32];
                x.copy_from_slice(&point.as_bytes()[1..33]);
                return Ok((private, x));
            }
            zeroize::Zeroize::zeroize(&mut private);
        }
        Err(Error::Protection)
    }
    fn p256_public_key(&mut self, private: &[u8; 32]) -> Result<[u8; 65], Error> {
        let secret = SecretKey::from_slice(private).map_err(|_| Error::Protection)?;
        let point = secret.public_key().to_sec1_point(false);
        let mut output = [0; 65];
        output.copy_from_slice(point.as_bytes());
        Ok(output)
    }
    fn p256_decompress(&mut self, x: &[u8; 32]) -> Result<[u8; 65], Error> {
        let mut encoded = [0; 33];
        encoded[0] = 2;
        encoded[1..].copy_from_slice(x);
        let public = PublicKey::from_sec1_bytes(&encoded).map_err(|_| Error::Protection)?;
        let point = public.to_sec1_point(false);
        let mut output = [0; 65];
        output.copy_from_slice(point.as_bytes());
        Ok(output)
    }
    fn p256_validate(&mut self, point: &[u8]) -> Result<(), Error> {
        PublicKey::from_sec1_bytes(point)
            .map(|_| ())
            .map_err(|_| Error::Protection)
    }
    fn p256_ecdh(&mut self, private: &[u8; 32], public_x: &[u8; 32]) -> Result<[u8; 32], Error> {
        let secret = SecretKey::from_slice(private).map_err(|_| Error::Protection)?;
        let encoded = self.p256_decompress(public_x)?;
        let public = PublicKey::from_sec1_bytes(&encoded).map_err(|_| Error::Protection)?;
        p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine())
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::Protection)
    }
    fn random(&mut self, output: &mut [u8]) {
        self.rng.fill_bytes(output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn cry_1_sha256_vectors_and_chunk_boundaries() {
        let mut provider = SoftwareCrypto::new(rand::rngs::StdRng::from_seed([0; 32]));
        let vectors = [
            (
                b"".as_slice(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".as_slice(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_slice(),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        // NIST SHA-256 vectors, including padding across a block boundary.
        for (input, expected) in vectors {
            let expected: std::vec::Vec<u8> = expected
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(provider.sha256(input).unwrap().as_slice(), expected);
            for split in 0..=input.len() {
                let mut state = provider.sha256_start().unwrap();
                state.update(&input[..split]).unwrap();
                state.update(&[]).unwrap();
                state.update(&input[split..]).unwrap();
                assert_eq!(state.finalize().unwrap().as_slice(), expected);
            }
        }
        // NIST's million-'a' vector exercises streams larger than the EDHOC buffers.
        let expected = [
            0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7,
            0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc,
            0xc7, 0x11, 0x2c, 0xd0,
        ];
        for chunk in [1, 55, 56, 63, 64, 65, 1000] {
            let mut state = provider.sha256_start().unwrap();
            let mut remaining = 1_000_000;
            while remaining > 0 {
                let n = remaining.min(chunk);
                state.update(&[b'a'; 1000][..n]).unwrap();
                remaining -= n;
            }
            assert_eq!(state.finalize().unwrap(), expected);
        }
        fn zeroizes<T: zeroize::ZeroizeOnDrop>() {}
        zeroizes::<Sha256>();
    }
}
