use mai_coap::{
    crypto::SoftwareCrypto,
    edhoc::{Identity, TrustedPeer},
    security::PeerId,
};
use std::{error::Error, fs};

pub fn credentials(
    ccs: &str,
    key: &str,
    peer: &str,
) -> Result<(Identity, TrustedPeer), Box<dyn Error>> {
    let private: [u8; 32] = fs::read(key)?
        .try_into()
        .map_err(|_| "private key must contain 32 raw bytes")?;
    let mut crypto = SoftwareCrypto::new(rand::rng());
    let own = Identity::new(&fs::read(ccs)?, private, &mut crypto)?;
    let peer = TrustedPeer::new(PeerId(1), &fs::read(peer)?)?;
    Ok((own, peer))
}
