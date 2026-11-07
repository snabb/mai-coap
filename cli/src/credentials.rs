//! EDHOC credentials: loading them for a run and generating new ones.
use crate::exit::Failure;
use mai_coap::{
    crypto::SoftwareCrypto,
    edhoc::{CcsEncoding, Identity, TrustedPeer},
    security::{CryptoProvider, PeerId},
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

/// The single trusted server of a run. A URI never selects a credential.
pub const SERVER: PeerId = PeerId(1);

/// The RFC 9052 COSE_Key `{1: 2, -1: 1, -4: d}` (EC2, P-256, 32-byte `d`) up to `d`, as
/// aiocoap-keygen writes it. Other encodings of a key, such as with `kid` or `x`, are refused.
const COSE_KEY_HEADER: [u8; 8] = [0xa3, 0x01, 0x02, 0x20, 0x01, 0x23, 0x58, 0x20];
const COSE_KEY_LEN: usize = COSE_KEY_HEADER.len() + 32;

fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    fs::read(path).map_err(|e| Failure::local(format!("{}: {e}", path.display())))
}

fn read_private_key(path: &Path) -> Result<[u8; 32], Failure> {
    let context = |e: &dyn std::fmt::Display| Failure::local(format!("{}: {e}", path.display()));
    let metadata = fs::metadata(path).map_err(|e| context(&e))?;
    if metadata.mode() & 0o077 != 0 {
        return Err(context(&"private key is accessible by other users"));
    }
    let file = Zeroizing::new(fs::read(path).map_err(|e| context(&e))?);
    file.strip_prefix(&COSE_KEY_HEADER)
        .and_then(|d| d.try_into().ok())
        .ok_or_else(|| context(&"not a P-256 COSE_Key of the form {1: 2, -1: 1, -4: d}"))
}

/// Loads a byte-exact identity and server credential.
pub fn load(
    identity: &Path,
    key: &Path,
    peer: &Path,
    crypto: &mut SoftwareCrypto<rand::rngs::ThreadRng>,
) -> Result<(Identity, TrustedPeer), Failure> {
    let private = read_private_key(key)?;
    let identity = Identity::new(&read(identity)?, private, crypto).map_err(|e| {
        Failure::local(format!(
            "{}: not a CCS matching the private key: {e}",
            identity.display()
        ))
    })?;
    let peer = TrustedPeer::new(SERVER, &read(peer)?)
        .map_err(|e| Failure::local(format!("{}: not a valid CCS: {e}", peer.display())))?;
    Ok((identity, peer))
}

fn with_extension(name: &Path, extension: &str) -> PathBuf {
    let mut path = name.as_os_str().to_owned();
    path.push(".");
    path.push(extension);
    PathBuf::from(path)
}

fn write_new(path: &Path, mode: u32, bytes: &[u8]) -> Result<(), Failure> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| Failure::local(format!("{}: {e}", path.display())))
}

/// Writes `NAME.ccs` and `NAME.cosekey`, refusing to replace either. Returns their paths.
pub fn generate(name: &Path, kid: Option<&[u8]>) -> Result<(PathBuf, PathBuf), Failure> {
    let (ccs_path, key_path) = (with_extension(name, "ccs"), with_extension(name, "cosekey"));
    if let Some(existing) = [&ccs_path, &key_path].into_iter().find(|p| p.exists()) {
        return Err(Failure::local(format!(
            "{}: already exists",
            existing.display()
        )));
    }
    let mut crypto = SoftwareCrypto::new(rand::rng());
    let (mut private, _) = crypto.p256_key_pair()?;
    let random_kid: [u8; 4] = rand::random();
    let identity = Identity::from_private_key(
        private,
        kid.unwrap_or(&random_kid),
        CcsEncoding::FullXY,
        &mut crypto,
    );
    let mut key = Zeroizing::new([0; COSE_KEY_LEN]);
    key[..COSE_KEY_HEADER.len()].copy_from_slice(&COSE_KEY_HEADER);
    key[COSE_KEY_HEADER.len()..].copy_from_slice(&private);
    let written = identity.map_err(Failure::from).and_then(|identity| {
        // The key goes first, so a failure can't leave a credential without its key.
        write_new(&key_path, 0o600, key.as_slice())?;
        write_new(&ccs_path, 0o644, identity.credential_bytes())
    });
    private.zeroize();
    written?;
    Ok((ccs_path, key_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    struct TempDirectory(PathBuf);
    impl TempDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "mai-coap-cli-{name}-{}-{:x}",
                std::process::id(),
                rand::random::<u32>()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn crypto() -> SoftwareCrypto<rand::rngs::ThreadRng> {
        SoftwareCrypto::new(rand::rng())
    }

    #[test]
    fn generated_identity_loads_and_key_is_private() {
        let directory = TempDirectory::new("generate");
        let (own_ccs, own_key) = generate(&directory.0.join("own"), Some(&[1, 2])).unwrap();
        let (peer_ccs, _) = generate(&directory.0.join("peer"), None).unwrap();
        assert_eq!(fs::metadata(&own_key).unwrap().mode() & 0o777, 0o600);
        let key = fs::read(&own_key).unwrap();
        assert_eq!(own_key.extension().unwrap(), "cosekey");
        assert_eq!(key.len(), 40);
        assert_eq!(key[..8], COSE_KEY_HEADER);
        let (identity, _) = load(&own_ccs, &own_key, &peer_ccs, &mut crypto()).unwrap();
        assert_eq!(identity.credential_bytes(), fs::read(&own_ccs).unwrap());
    }

    #[test]
    fn generate_refuses_to_replace_existing_files() {
        let directory = TempDirectory::new("replace");
        let name = directory.0.join("own");
        let (_, key) = generate(&name, None).unwrap();
        let before = fs::read(&key).unwrap();
        assert!(
            generate(&name, None)
                .unwrap_err()
                .message
                .contains("exists")
        );
        assert_eq!(fs::read(&key).unwrap(), before);
    }

    #[test]
    fn generate_leaves_no_new_key_when_only_the_credential_exists() {
        let directory = TempDirectory::new("partial");
        let name = directory.0.join("own");
        write_new(&with_extension(&name, "ccs"), 0o644, b"existing").unwrap();
        assert!(
            generate(&name, None)
                .unwrap_err()
                .message
                .contains("exists")
        );
        assert!(!with_extension(&name, "cosekey").exists());
    }

    #[test]
    fn load_refuses_exposed_or_malformed_keys_and_mismatched_credentials() {
        let directory = TempDirectory::new("load");
        let (ccs, key) = generate(&directory.0.join("own"), None).unwrap();
        let (other_ccs, other_key) = generate(&directory.0.join("other"), None).unwrap();

        fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
        let error = load(&ccs, &key, &other_ccs, &mut crypto()).unwrap_err();
        assert!(error.message.contains("other users"), "{}", error.message);
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let short = directory.0.join("short.cosekey");
        write_new(&short, 0o600, &[0; 31]).unwrap();
        let error = load(&ccs, &short, &other_ccs, &mut crypto()).unwrap_err();
        assert!(error.message.contains("COSE_Key"), "{}", error.message);

        let error = load(&ccs, &other_key, &other_ccs, &mut crypto()).unwrap_err();
        assert!(error.message.contains("matching"), "{}", error.message);

        let error = load(&ccs, &key, &short, &mut crypto()).unwrap_err();
        assert!(error.message.contains("valid CCS"), "{}", error.message);
    }

    /// RFC 9052 section 7.1 and RFC 9053 section 7.1.1: kty 1 is EC2 (2), crv -1 is P-256 (1),
    /// and d is -4. Written independently of `COSE_KEY_HEADER`.
    #[test]
    fn load_accepts_only_the_cose_key_layout() {
        let directory = TempDirectory::new("layout");
        let (ccs, key) = generate(&directory.0.join("own"), None).unwrap();
        let (peer, _) = generate(&directory.0.join("peer"), None).unwrap();
        let file = fs::read(&key).unwrap();
        let d = &file[8..];
        let cose_key = |prefix: &[u8], suffix: &[u8]| [prefix, d, suffix].concat();
        let accepted = cose_key(&[0xa3, 0x01, 0x02, 0x20, 0x01, 0x23, 0x58, 0x20], &[]);
        let refused = [
            ("raw", d.to_vec()),
            (
                "P-384",
                cose_key(&[0xa3, 0x01, 0x02, 0x20, 0x02, 0x23, 0x58, 0x20], &[]),
            ),
            (
                "OKP",
                cose_key(&[0xa3, 0x01, 0x01, 0x20, 0x01, 0x23, 0x58, 0x20], &[]),
            ),
            (
                "x not d",
                cose_key(&[0xa3, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20], &[]),
            ),
            (
                "two entries",
                cose_key(&[0xa2, 0x01, 0x02, 0x20, 0x01, 0x23, 0x58, 0x20], &[]),
            ),
            (
                "trailing",
                cose_key(&[0xa3, 0x01, 0x02, 0x20, 0x01, 0x23, 0x58, 0x20], &[0]),
            ),
            ("truncated", file[..39].to_vec()),
        ];
        for (name, bytes) in std::iter::once(("accepted", accepted)).chain(refused) {
            let path = directory.0.join(name);
            write_new(&path, 0o600, &bytes).unwrap();
            let result = load(&ccs, &path, &peer, &mut crypto());
            if name == "accepted" {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert!(
                    error.message.contains("COSE_Key"),
                    "{name}: {}",
                    error.message
                );
            }
        }
    }
}
