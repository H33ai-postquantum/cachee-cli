//! Content-addressed persistent storage using sled embedded database.
//! Every bundle is stored and retrievable by SHA3-256(primitive || content_hash || fingerprint).
//! Immutable: delete requires an attestation record.

use sled::Db;
use std::path::Path;

use crate::archive::CacheeArchiveBundle;

pub struct ContentStore {
    db: Db,
    /// Count of stored bundles
    count: std::sync::atomic::AtomicU64,
}

impl ContentStore {
    /// Open or create a content store at the given path.
    pub fn open(path: &Path) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("Failed to open content store: {}", e))?;
        let count = db.len() as u64;
        Ok(Self {
            db,
            count: std::sync::atomic::AtomicU64::new(count),
        })
    }

    /// Store a bundle by its content address. Returns the address.
    pub fn put(&self, bundle: &CacheeArchiveBundle) -> Result<[u8; 32], String> {
        let address = bundle.content_address();
        let bytes = bundle.serialize();
        self.db
            .insert(address.as_slice(), bytes.as_slice())
            .map_err(|e| format!("Content store write failed: {}", e))?;
        self.db
            .flush()
            .map_err(|e| format!("Content store flush failed: {}", e))?;
        self.count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(address)
    }

    /// Retrieve a bundle by its content address.
    pub fn get(&self, address: &[u8; 32]) -> Result<Option<CacheeArchiveBundle>, String> {
        match self
            .db
            .get(address.as_slice())
            .map_err(|e| format!("Content store read failed: {}", e))?
        {
            Some(bytes) => {
                let bundle = CacheeArchiveBundle::deserialize(&bytes)
                    .map_err(|e| format!("Bundle deserialization failed: {}", e))?;
                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }

    /// Check if a bundle exists.
    pub fn exists(&self, address: &[u8; 32]) -> bool {
        self.db.contains_key(address.as_slice()).unwrap_or(false)
    }

    /// Export a bundle to a file path as a .cab file.
    pub fn export(&self, address: &[u8; 32], dest: &Path) -> Result<(), String> {
        let bundle = self
            .get(address)?
            .ok_or_else(|| format!("Bundle not found: {}", hex::encode(address)))?;
        let bytes = bundle.serialize();
        std::fs::write(dest, &bytes).map_err(|e| format!("Export write failed: {}", e))?;
        Ok(())
    }

    /// Export all bundles to a directory.
    pub fn export_all(&self, dest_dir: &Path) -> Result<u64, String> {
        std::fs::create_dir_all(dest_dir)
            .map_err(|e| format!("Failed to create export dir: {}", e))?;

        let mut count = 0u64;
        for item in self.db.iter() {
            let (key, value) = item.map_err(|e| format!("Iterator error: {}", e))?;
            let filename = format!("{}.cab", hex::encode(&key));
            let path = dest_dir.join(&filename);
            std::fs::write(&path, value.as_ref())
                .map_err(|e| format!("Write failed for {}: {}", filename, e))?;
            count += 1;
        }
        Ok(count)
    }

    /// Number of stored bundles.
    pub fn len(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Iterate over all content addresses.
    pub fn addresses(&self) -> Vec<[u8; 32]> {
        self.db
            .iter()
            .filter_map(|item| {
                let (key, _) = item.ok()?;
                if key.len() == 32 {
                    let mut addr = [0u8; 32];
                    addr.copy_from_slice(&key);
                    Some(addr)
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_bundle() -> CacheeArchiveBundle {
        // Create a minimal valid bundle with real PQ signatures
        let content = b"test cached computation result";
        let content_hash = crate::cache_slot::sha3_256(content);

        let crypto_bundle = crate::crypto::generate_test_bundle(&content_hash);

        CacheeArchiveBundle {
            magic: crate::archive::CAB_MAGIC,
            version: 1,
            primitive: crate::archive::H33Primitive {
                version: 1,
                timestamp: [0u8; 8],
                value_hash: content_hash,
                mldsa_prefix: [crypto_bundle.mldsa_sig[0], crypto_bundle.mldsa_sig[1]],
                falcon_prefix: [crypto_bundle.falcon_sig[0], crypto_bundle.falcon_sig[1]],
                slhdsa_prefix: [crypto_bundle.slhdsa_sig[0], crypto_bundle.slhdsa_sig[1]],
                flags: [0u8; 11],
            },
            content_hash,
            computation_type: crate::archive::ComputationType::DocumentAttest,
            timestamp_ns: 1776000000000000000,
            signer_keys: crate::archive::SignerPublicKeys {
                mldsa65: crypto_bundle.mldsa_pk,
                falcon512: crypto_bundle.falcon_pk,
                slhdsa128f: crypto_bundle.slhdsa_pk,
            },
            signatures: crate::archive::SignatureBundle {
                mldsa65: crypto_bundle.mldsa_sig,
                falcon512: crypto_bundle.falcon_sig,
                slhdsa128f: crypto_bundle.slhdsa_sig,
            },
            metadata: vec![],
            on_chain_anchor: None,
            completeness: crate::archive::CompletenessLevel::Complete,
            computation_fingerprint: crate::archive::ComputationFingerprint::empty(),
            signer_identity: crate::archive::SignerIdentity::default(),
        }
    }

    #[test]
    fn test_put_and_get() {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::open(dir.path()).unwrap();
        let bundle = make_test_bundle();

        let address = store.put(&bundle).unwrap();
        assert!(store.exists(&address));

        let retrieved = store.get(&address).unwrap().unwrap();
        assert_eq!(retrieved.content_hash, bundle.content_hash);
    }

    #[test]
    fn test_export() {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::open(dir.path().join("store").as_path()).unwrap();
        let bundle = make_test_bundle();

        let address = store.put(&bundle).unwrap();
        let export_path = dir.path().join("export.cab");
        store.export(&address, &export_path).unwrap();

        assert!(export_path.exists());
        let bytes = std::fs::read(&export_path).unwrap();
        let loaded = CacheeArchiveBundle::deserialize(&bytes).unwrap();
        assert_eq!(loaded.content_hash, bundle.content_hash);
    }

    #[test]
    fn test_real_crypto_verification() {
        let bundle = make_test_bundle();
        let result = bundle.verify();
        assert!(result.mldsa_valid());
        assert!(result.falcon_valid());
        assert!(result.slhdsa_valid());
        assert!(result.valid());
        assert!(result.two_of_three());
    }

    #[test]
    fn test_export_all() {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::open(dir.path().join("store").as_path()).unwrap();

        let bundle1 = make_test_bundle();
        store.put(&bundle1).unwrap();

        let export_dir = dir.path().join("exports");
        let count = store.export_all(&export_dir).unwrap();
        assert_eq!(count, 1);

        // Check that .cab file exists
        let entries: Vec<_> = std::fs::read_dir(&export_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0]
            .path()
            .extension()
            .map_or(false, |ext| ext == "cab"));
    }

    #[test]
    fn test_addresses() {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::open(dir.path()).unwrap();
        let bundle = make_test_bundle();

        let address = store.put(&bundle).unwrap();
        let addrs = store.addresses();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], address);
    }

    #[test]
    fn test_nonexistent_get() {
        let dir = TempDir::new().unwrap();
        let store = ContentStore::open(dir.path()).unwrap();
        let fake_addr = [0xffu8; 32];
        assert!(store.get(&fake_addr).unwrap().is_none());
        assert!(!store.exists(&fake_addr));
    }

    #[test]
    fn test_export_determinism() {
        let bundle = make_test_bundle();
        let bytes1 = bundle.serialize();
        let bytes2 = bundle.serialize();
        assert_eq!(bytes1, bytes2, "Repeated serialization must produce identical bytes");
    }
}
