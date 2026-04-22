//! Static Noise keypair management.
//!
//! On disk the keypair is stored as a single 64-byte file:
//!   `[0..32] = private key`
//!   `[32..64] = public key`
//!
//! The public key is persisted alongside the private to avoid pulling in
//! a separate X25519 crate just to re-derive it on load — snow's keypair
//! generator already emits both halves, and they never change after first
//! write.
//!
//! File perms are `0600` on Unix. Overwriting an existing key file is
//! refused (`load_or_generate` only generates when the file is absent).

use anyhow::{bail, Context, Result};
use snow::params::NoiseParams;
use snow::Builder;
use std::fs;
use std::path::Path;

const PARAMS: &str = "Noise_NX_25519_ChaChaPoly_BLAKE2s";
const KEY_FILE_LEN: usize = 64;

/// Curve25519 static keypair for a Noise NX responder (TP / pool).
#[derive(Clone)]
pub struct StaticKeys {
    /// X25519 private scalar (32 bytes).
    pub private: [u8; 32],
    /// X25519 public key (32 bytes, base-point * private).
    pub public: [u8; 32],
}

impl StaticKeys {
    /// Generate a fresh keypair.
    pub fn generate() -> Result<Self> {
        let params: NoiseParams = PARAMS.parse().expect("static noise params");
        let kp = Builder::new(params)
            .generate_keypair()
            .context("snow generate_keypair")?;
        if kp.private.len() != 32 || kp.public.len() != 32 {
            bail!(
                "unexpected key size: priv={} pub={}",
                kp.private.len(),
                kp.public.len()
            );
        }
        let mut private = [0u8; 32];
        private.copy_from_slice(&kp.private);
        let mut public = [0u8; 32];
        public.copy_from_slice(&kp.public);
        Ok(Self { private, public })
    }

    /// Load keys from `path`, or generate and persist them if the file
    /// does not exist.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let data = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            if data.len() != KEY_FILE_LEN {
                bail!(
                    "{}: expected {} bytes, got {}",
                    path.display(),
                    KEY_FILE_LEN,
                    data.len()
                );
            }
            let mut private = [0u8; 32];
            private.copy_from_slice(&data[..32]);
            let mut public = [0u8; 32];
            public.copy_from_slice(&data[32..]);
            return Ok(Self { private, public });
        }

        let keys = Self::generate()?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).ok();
            }
        }
        let mut out = [0u8; KEY_FILE_LEN];
        out[..32].copy_from_slice(&keys.private);
        out[32..].copy_from_slice(&keys.public);
        fs::write(path, out).with_context(|| format!("writing {}", path.display()))?;
        restrict_perms(path)?;
        Ok(keys)
    }

    /// Hex-encoded public key for publication.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }
}

#[cfg(unix)]
fn restrict_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    #[test]
    fn generate_produces_32_32() {
        let k = StaticKeys::generate().unwrap();
        assert_ne!(k.private, [0u8; 32]);
        assert_ne!(k.public, [0u8; 32]);
    }

    #[test]
    fn load_or_generate_persists_stable_pubkey() {
        let path = temp_dir().join(format!(
            "dinero-sv2-transport-test-{}.key",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let a = StaticKeys::load_or_generate(&path).unwrap();
        let b = StaticKeys::load_or_generate(&path).unwrap();
        assert_eq!(a.private, b.private);
        assert_eq!(a.public, b.public);
        fs::remove_file(&path).ok();
    }
}
