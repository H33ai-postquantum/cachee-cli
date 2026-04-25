//! PQ key management — generate, load, and persist post-quantum keypairs.
//!
//! Keys are generated on `cachee init` and stored at `~/.cachee/keys/`.
//! The daemon loads them on startup and uses them for signing every SET
//! when attestation is enabled.

use pqcrypto_dilithium::dilithium3;
use pqcrypto_falcon::falcon512;
use pqcrypto_sphincsplus::sphincssha2128fsimple;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

/// Post-quantum key set with all three NIST-standardized families.
///
/// # Key storage security
///
/// Current implementation: filesystem with 0o600 permissions.
///
/// ## Security roadmap
/// - [ ] Passphrase wrapping (AES-256-GCM envelope)
/// - [ ] OS keychain integration (macOS Keychain, Linux secret-tool)
/// - [ ] KMS integration (AWS KMS, Azure Key Vault, GCP Cloud KMS)
/// - [ ] HSM support (PKCS#11, Nitrokey, YubiHSM)
/// - [ ] Non-exportable mode (keys generated and used inside HSM only)
/// - [ ] Backup/recovery with Shamir secret sharing
///
/// ## Key lifecycle
/// - Keys are generated on `cachee init` with a specified `CryptoPosture`
/// - Key rotation via `rotate()` links new keys to predecessor via `rotated_from`
/// - Key revocation sets `metadata.revoked = true`
/// - Old keys are retained for verification of existing bundles
pub struct PqKeySet {
    pub mldsa_pk: Vec<u8>,
    pub mldsa_sk: Vec<u8>,
    pub falcon_pk: Vec<u8>,
    pub falcon_sk: Vec<u8>,
    pub slhdsa_pk: Vec<u8>,
    pub slhdsa_sk: Vec<u8>,
    pub metadata: KeyMetadata,
}

/// Result of signing a message with all three PQ families.
pub struct SignResult {
    pub mldsa_sig: Vec<u8>,
    pub falcon_sig: Vec<u8>,
    pub slhdsa_sig: Vec<u8>,
}

/// Key metadata — versioning, creation, rotation tracking
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyMetadata {
    pub key_id: [u8; 32],
    pub version: u32,
    pub created_at: u64,
    pub last_used_at: u64,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub rotated_from: Option<[u8; 32]>,
    pub posture: CryptoPosture,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum CryptoPosture {
    Development,
    Testing,
    Production,
}

fn compute_key_id(mldsa_pk: &[u8], falcon_pk: &[u8], slhdsa_pk: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(mldsa_pk);
    hasher.update(falcon_pk);
    hasher.update(slhdsa_pk);
    let r = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

impl PqKeySet {
    /// Generate fresh keypairs for all three families.
    pub fn generate(posture: CryptoPosture) -> Self {
        let (mldsa_pk, mldsa_sk) = dilithium3::keypair();
        let (falcon_pk, falcon_sk) = falcon512::keypair();
        let (slhdsa_pk, slhdsa_sk) = sphincssha2128fsimple::keypair();

        let mldsa_pk_bytes = mldsa_pk.as_bytes().to_vec();
        let falcon_pk_bytes = falcon_pk.as_bytes().to_vec();
        let slhdsa_pk_bytes = slhdsa_pk.as_bytes().to_vec();

        let key_id = compute_key_id(&mldsa_pk_bytes, &falcon_pk_bytes, &slhdsa_pk_bytes);
        let now = now_ns();

        Self {
            mldsa_pk: mldsa_pk_bytes,
            mldsa_sk: mldsa_sk.as_bytes().to_vec(),
            falcon_pk: falcon_pk_bytes,
            falcon_sk: falcon_sk.as_bytes().to_vec(),
            slhdsa_pk: slhdsa_pk_bytes,
            slhdsa_sk: slhdsa_sk.as_bytes().to_vec(),
            metadata: KeyMetadata {
                key_id,
                version: 1,
                created_at: now,
                last_used_at: now,
                expires_at: None,
                revoked: false,
                rotated_from: None,
                posture,
            },
        }
    }

    /// Save keypairs to disk at the given directory.
    /// Private keys are stored with restricted permissions (0o600).
    pub fn save(&self, keys_dir: &std::path::Path) -> Result<(), String> {
        std::fs::create_dir_all(keys_dir).map_err(|e| format!("mkdir: {}", e))?;

        // Public keys
        std::fs::write(keys_dir.join("mldsa65.pub"), &self.mldsa_pk)
            .map_err(|e| format!("write mldsa pk: {}", e))?;
        std::fs::write(keys_dir.join("falcon512.pub"), &self.falcon_pk)
            .map_err(|e| format!("write falcon pk: {}", e))?;
        std::fs::write(keys_dir.join("slhdsa128f.pub"), &self.slhdsa_pk)
            .map_err(|e| format!("write slhdsa pk: {}", e))?;

        // Private keys
        std::fs::write(keys_dir.join("mldsa65.key"), &self.mldsa_sk)
            .map_err(|e| format!("write mldsa sk: {}", e))?;
        std::fs::write(keys_dir.join("falcon512.key"), &self.falcon_sk)
            .map_err(|e| format!("write falcon sk: {}", e))?;
        std::fs::write(keys_dir.join("slhdsa128f.key"), &self.slhdsa_sk)
            .map_err(|e| format!("write slhdsa sk: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let restricted = std::fs::Permissions::from_mode(0o600);
            for name in &["mldsa65.key", "falcon512.key", "slhdsa128f.key"] {
                let _ = std::fs::set_permissions(keys_dir.join(name), restricted.clone());
            }
        }

        // Write key metadata
        let metadata_json = serde_json::to_string_pretty(&self.metadata)
            .map_err(|e| format!("serialize metadata: {}", e))?;
        std::fs::write(keys_dir.join("metadata.json"), &metadata_json)
            .map_err(|e| format!("write metadata: {}", e))?;

        Ok(())
    }

    /// Load keypairs from disk.
    pub fn load(keys_dir: &std::path::Path) -> Result<Self, String> {
        let read = |name: &str| -> Result<Vec<u8>, String> {
            std::fs::read(keys_dir.join(name))
                .map_err(|e| format!("read {}: {}", name, e))
        };

        let mldsa_pk = read("mldsa65.pub")?;
        let falcon_pk = read("falcon512.pub")?;
        let slhdsa_pk = read("slhdsa128f.pub")?;

        // Load metadata with backward-compatible fallback
        let metadata = match std::fs::read_to_string(keys_dir.join("metadata.json")) {
            Ok(json_str) => serde_json::from_str::<KeyMetadata>(&json_str)
                .unwrap_or_else(|_| KeyMetadata {
                    key_id: compute_key_id(&mldsa_pk, &falcon_pk, &slhdsa_pk),
                    version: 1,
                    created_at: 0,
                    last_used_at: 0,
                    expires_at: None,
                    revoked: false,
                    rotated_from: None,
                    posture: CryptoPosture::Production,
                }),
            Err(_) => KeyMetadata {
                key_id: compute_key_id(&mldsa_pk, &falcon_pk, &slhdsa_pk),
                version: 1,
                created_at: 0,
                last_used_at: 0,
                expires_at: None,
                revoked: false,
                rotated_from: None,
                posture: CryptoPosture::Production,
            },
        };

        Ok(Self {
            mldsa_pk,
            mldsa_sk: read("mldsa65.key")?,
            falcon_pk,
            falcon_sk: read("falcon512.key")?,
            slhdsa_pk,
            slhdsa_sk: read("slhdsa128f.key")?,
            metadata,
        })
    }

    /// Check if keys exist on disk.
    pub fn exists(keys_dir: &std::path::Path) -> bool {
        keys_dir.join("mldsa65.pub").exists()
            && keys_dir.join("mldsa65.key").exists()
            && keys_dir.join("falcon512.pub").exists()
            && keys_dir.join("falcon512.key").exists()
            && keys_dir.join("slhdsa128f.pub").exists()
            && keys_dir.join("slhdsa128f.key").exists()
    }

    /// Sign the content hash (standard scope -- covers computation result).
    /// This is the default signing scope for all SET operations.
    pub fn sign_content(&self, content_hash: &[u8; 32]) -> SignResult {
        self.sign(content_hash)
    }

    /// Sign the full content address (extended scope -- covers result + fingerprint).
    /// Use for full-scope attestation where computation identity must be bound.
    pub fn sign_content_address(&self, content_address: &[u8; 32]) -> SignResult {
        self.sign(content_address)
    }

    /// Sign a message with all three families. Returns the three signatures.
    pub fn sign(&self, message: &[u8]) -> SignResult {
        use pqcrypto_traits::sign::DetachedSignature;

        let mldsa_sk = dilithium3::SecretKey::from_bytes(&self.mldsa_sk)
            .expect("invalid ML-DSA secret key");
        let mldsa_sig = dilithium3::detached_sign(message, &mldsa_sk);

        let falcon_sk = falcon512::SecretKey::from_bytes(&self.falcon_sk)
            .expect("invalid FALCON secret key");
        let falcon_sig = falcon512::detached_sign(message, &falcon_sk);

        let slhdsa_sk = sphincssha2128fsimple::SecretKey::from_bytes(&self.slhdsa_sk)
            .expect("invalid SLH-DSA secret key");
        let slhdsa_sig = sphincssha2128fsimple::detached_sign(message, &slhdsa_sk);

        SignResult {
            mldsa_sig: mldsa_sig.as_bytes().to_vec(),
            falcon_sig: falcon_sig.as_bytes().to_vec(),
            slhdsa_sig: slhdsa_sig.as_bytes().to_vec(),
        }
    }

    /// Get the public keys as a SignerPublicKeys struct (for CAB bundles).
    pub fn public_keys(&self) -> crate::archive::SignerPublicKeys {
        crate::archive::SignerPublicKeys {
            mldsa65: self.mldsa_pk.clone(),
            falcon512: self.falcon_pk.clone(),
            slhdsa128f: self.slhdsa_pk.clone(),
        }
    }

    /// Rotate keys: generate a new keyset, incrementing version and linking
    /// to the previous key_id.
    pub fn rotate(&self) -> Self {
        let mut new = Self::generate(self.metadata.posture.clone());
        new.metadata.version = self.metadata.version + 1;
        new.metadata.rotated_from = Some(self.metadata.key_id);
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_sign_verify() {
        let keys = PqKeySet::generate(CryptoPosture::Production);
        let message = b"test message for signing";
        let sigs = keys.sign(message);

        let result = crate::crypto::verify_all(
            message,
            &keys.mldsa_pk, &sigs.mldsa_sig,
            &keys.falcon_pk, &sigs.falcon_sig,
            &keys.slhdsa_pk, &sigs.slhdsa_sig,
        );
        assert!(result.all_valid);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let keys = PqKeySet::generate(CryptoPosture::Production);
        let dir = std::env::temp_dir().join("cachee_test_keys");
        let _ = std::fs::remove_dir_all(&dir);
        keys.save(&dir).unwrap();

        let loaded = PqKeySet::load(&dir).unwrap();
        assert_eq!(keys.mldsa_pk, loaded.mldsa_pk);
        assert_eq!(keys.falcon_pk, loaded.falcon_pk);
        assert_eq!(keys.slhdsa_pk, loaded.slhdsa_pk);
        assert_eq!(keys.metadata.key_id, loaded.metadata.key_id);
        assert_eq!(keys.metadata.version, loaded.metadata.version);

        // Sign with loaded keys, verify
        let message = b"roundtrip test";
        let sigs = loaded.sign(message);
        let result = crate::crypto::verify_all(
            message,
            &loaded.mldsa_pk, &sigs.mldsa_sig,
            &loaded.falcon_pk, &sigs.falcon_sig,
            &loaded.slhdsa_pk, &sigs.slhdsa_sig,
        );
        assert!(result.all_valid);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
