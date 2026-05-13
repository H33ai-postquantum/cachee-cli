//! Hash-chained audit log — tamper-evident, persistent, replayable.
//!
//! Every state transition, verification event, and command execution produces
//! an AuditEntry. Entries are hash-chained: each entry includes the hash of
//! the previous entry, making deletion, reordering, and modification detectable.
//!
//! Storage: sled database at `~/.cachee/audit_log`.
//!
//! Chain integrity: `entry.hash = SHA3-256(prev_hash || entry_bytes)`.
//! Verify with `cachee audit verify` — walks the chain and checks every link.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

/// The types of events recorded in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// A state transition on a CacheSlot.
    StateTransition {
        key: String,
        from_state: String,
        to_state: String,
        authority: String,
        reason: Option<String>,
    },
    /// A cryptographic verification was performed on read.
    VerificationPerformed {
        key: String,
        mldsa_valid: bool,
        falcon_valid: bool,
        slhdsa_valid: bool,
        two_of_three: bool,
        all_three: bool,
    },
    /// A verification failed on read.
    VerificationFailed { key: String, error: String },
    /// A new entry was created (SET with attestation).
    EntryCreated {
        key: String,
        content_address: String,
        fingerprint_digest: String,
        signed: bool,
    },
    /// An entry was deleted.
    EntryDeleted { key: String },
    /// Key rotation event.
    KeyRotation {
        old_key_id: u64,
        new_key_id: u64,
        old_version: u32,
        new_version: u32,
    },
    /// Daemon started.
    DaemonStart {
        version: String,
        attest_enabled: bool,
        verify_mode: String,
    },
    /// Command rejected due to replay (duplicate nonce).
    ReplayRejected { command: String, nonce: String },
    /// Merkle root anchor computed over audit entries.
    MerkleAnchor {
        /// Merkle root of all entries since last anchor.
        merkle_root: String,
        /// First sequence included in this anchor.
        from_sequence: u64,
        /// Last sequence included in this anchor.
        to_sequence: u64,
        /// Number of entries in this anchor.
        entry_count: u64,
    },
}

/// A single entry in the hash-chained audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Monotonic sequence number (0-indexed).
    pub sequence: u64,
    /// SHA3-256 hash of the previous entry (zeros for genesis).
    pub prev_hash: [u8; 32],
    /// SHA3-256 hash of this entry (computed over prev_hash || event_bytes).
    pub hash: [u8; 32],
    /// Nanosecond timestamp (monotonic within this process).
    pub timestamp_ns: u64,
    /// The event that occurred.
    pub event: AuditEventType,
    /// Issuer ID of the node that produced this event.
    pub issuer_id: String,
}

impl AuditEntry {
    /// Compute the hash of this entry: SHA3-256(prev_hash || event_serialized).
    fn compute_hash(
        prev_hash: &[u8; 32],
        event: &AuditEventType,
        timestamp_ns: u64,
        sequence: u64,
    ) -> [u8; 32] {
        let event_bytes = serde_json::to_vec(event).unwrap_or_default();
        let mut hasher = Sha3_256::new();
        hasher.update(prev_hash);
        hasher.update(timestamp_ns.to_be_bytes());
        hasher.update(sequence.to_be_bytes());
        hasher.update(&event_bytes);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Persistent, hash-chained audit log backed by sled.
pub struct AuditLog {
    db: sled::Db,
    /// Current chain head hash.
    head_hash: [u8; 32],
    /// Next sequence number.
    next_sequence: u64,
    /// Issuer ID for this node.
    issuer_id: String,
    /// Nonce tracking — prevents replay of commands.
    seen_nonces: HashSet<[u8; 32]>,
    /// Merkle tree of audit entry hashes (for periodic anchoring).
    merkle_leaves: Vec<[u8; 32]>,
    /// Last Merkle root (anchored).
    last_merkle_root: Option<[u8; 32]>,
    /// Sequence number at last Merkle anchor.
    last_anchor_sequence: u64,
}

impl AuditLog {
    /// Open or create an audit log at the given path.
    pub fn open(path: &std::path::Path, issuer_id: &str) -> Result<Self, String> {
        let db = sled::open(path).map_err(|e| format!("audit log open: {}", e))?;

        // Find the last entry to recover chain state
        let (head_hash, next_sequence) =
            if let Some(last) = db.last().map_err(|e| format!("audit scan: {}", e))? {
                let entry: AuditEntry = serde_json::from_slice(&last.1)
                    .map_err(|e| format!("audit deserialize: {}", e))?;
                (entry.hash, entry.sequence + 1)
            } else {
                ([0u8; 32], 0)
            };

        // Rebuild merkle leaves from existing entries
        let mut merkle_leaves = Vec::new();
        for (_k, v) in db.iter().flatten() {
            if let Ok(entry) = serde_json::from_slice::<AuditEntry>(&v) {
                merkle_leaves.push(entry.hash);
            }
        }

        Ok(Self {
            db,
            head_hash,
            next_sequence,
            issuer_id: issuer_id.to_string(),
            seen_nonces: HashSet::new(),
            merkle_leaves,
            last_merkle_root: None,
            last_anchor_sequence: 0,
        })
    }

    /// Append an event to the audit log. Returns the entry's hash.
    pub fn append(&mut self, event: AuditEventType) -> Result<[u8; 32], String> {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let hash =
            AuditEntry::compute_hash(&self.head_hash, &event, timestamp_ns, self.next_sequence);

        let entry = AuditEntry {
            sequence: self.next_sequence,
            prev_hash: self.head_hash,
            hash,
            timestamp_ns,
            event,
            issuer_id: self.issuer_id.clone(),
        };

        let entry_bytes =
            serde_json::to_vec(&entry).map_err(|e| format!("audit serialize: {}", e))?;

        // Key = sequence number as big-endian bytes (maintains order in sled)
        self.db
            .insert(self.next_sequence.to_be_bytes(), entry_bytes)
            .map_err(|e| format!("audit write: {}", e))?;

        self.db.flush().map_err(|e| format!("audit flush: {}", e))?;

        self.head_hash = hash;
        self.next_sequence += 1;
        self.merkle_leaves.push(hash);

        Ok(hash)
    }

    /// Verify the entire chain. Returns (valid_count, first_broken_sequence).
    pub fn verify_chain(&self) -> Result<(u64, Option<u64>), String> {
        let mut prev_hash = [0u8; 32];
        let mut count = 0u64;

        for item in self.db.iter() {
            let (_key, value) = item.map_err(|e| format!("audit read: {}", e))?;
            let entry: AuditEntry =
                serde_json::from_slice(&value).map_err(|e| format!("audit deserialize: {}", e))?;

            // Verify prev_hash link
            if entry.prev_hash != prev_hash {
                return Ok((count, Some(entry.sequence)));
            }

            // Recompute and verify hash
            let expected = AuditEntry::compute_hash(
                &entry.prev_hash,
                &entry.event,
                entry.timestamp_ns,
                entry.sequence,
            );
            if entry.hash != expected {
                return Ok((count, Some(entry.sequence)));
            }

            prev_hash = entry.hash;
            count += 1;
        }

        Ok((count, None))
    }

    /// Get the full lifecycle history for a specific key.
    pub fn key_history(&self, key: &str) -> Vec<AuditEntry> {
        let mut history = Vec::new();
        for (_k, v) in self.db.iter().flatten() {
            if let Ok(entry) = serde_json::from_slice::<AuditEntry>(&v) {
                let matches = match &entry.event {
                    AuditEventType::StateTransition { key: k, .. } => k == key,
                    AuditEventType::VerificationPerformed { key: k, .. } => k == key,
                    AuditEventType::VerificationFailed { key: k, .. } => k == key,
                    AuditEventType::EntryCreated { key: k, .. } => k == key,
                    AuditEventType::EntryDeleted { key: k, .. } => k == key,
                    _ => false,
                };
                if matches {
                    history.push(entry);
                }
            }
        }
        history
    }

    /// Check and register a nonce. Returns false if nonce was already seen (replay).
    pub fn check_nonce(&mut self, nonce: &[u8; 32]) -> bool {
        if self.seen_nonces.contains(nonce) {
            false
        } else {
            self.seen_nonces.insert(*nonce);
            // Cap nonce set at 100K to prevent unbounded growth
            if self.seen_nonces.len() > 100_000 {
                // In production, use a time-windowed bloom filter instead
                self.seen_nonces.clear();
                self.seen_nonces.insert(*nonce);
            }
            true
        }
    }

    /// Compute Merkle root of all entries since last anchor.
    /// Anchors the audit chain — call periodically (e.g., every 1000 entries or every hour).
    pub fn compute_merkle_anchor(&mut self) -> Result<[u8; 32], String> {
        let leaves_since_anchor: Vec<[u8; 32]> = self
            .merkle_leaves
            .iter()
            .skip(self.last_anchor_sequence as usize)
            .copied()
            .collect();

        if leaves_since_anchor.is_empty() {
            return Err("no entries since last anchor".into());
        }

        let root = Self::merkle_root(&leaves_since_anchor);
        let from_seq = self.last_anchor_sequence;
        let to_seq = self.next_sequence.saturating_sub(1);
        let count = leaves_since_anchor.len() as u64;

        // Record the anchor as an audit event
        self.append(AuditEventType::MerkleAnchor {
            merkle_root: hex::encode(root),
            from_sequence: from_seq,
            to_sequence: to_seq,
            entry_count: count,
        })?;

        self.last_merkle_root = Some(root);
        self.last_anchor_sequence = self.next_sequence;

        Ok(root)
    }

    /// Compute Merkle root from a set of leaf hashes.
    fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha3_256::new();
                hasher.update(chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(chunk[1]);
                } else {
                    // Odd number: hash with itself
                    hasher.update(chunk[0]);
                }
                let result = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&result);
                next_level.push(out);
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Export the full lifecycle of a key as a JSON array — one command.
    /// This is the "reconstruct full lifecycle from genesis to now" requirement.
    pub fn export_key_lifecycle(&self, key: &str) -> String {
        let history = self.key_history(key);
        serde_json::to_string_pretty(&history).unwrap_or_else(|_| "[]".to_string())
    }

    /// Export the entire audit log as a verifiable JSON array.
    pub fn export_all(&self) -> Vec<AuditEntry> {
        let mut entries = Vec::new();
        for (_k, v) in self.db.iter().flatten() {
            if let Ok(entry) = serde_json::from_slice::<AuditEntry>(&v) {
                entries.push(entry);
            }
        }
        entries
    }

    /// Get the last Merkle root (if anchored).
    pub fn last_anchor(&self) -> Option<[u8; 32]> {
        self.last_merkle_root
    }

    /// Total entries in the log.
    pub fn len(&self) -> u64 {
        self.next_sequence
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.next_sequence == 0
    }

    /// Current chain head hash.
    pub fn head(&self) -> [u8; 32] {
        self.head_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_append_and_verify() {
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), "test-node").unwrap();

        // Append 3 events
        log.append(AuditEventType::DaemonStart {
            version: "0.3.0".to_string(),
            attest_enabled: true,
            verify_mode: "always".to_string(),
        })
        .unwrap();

        log.append(AuditEventType::EntryCreated {
            key: "my-key".to_string(),
            content_address: "abc123".to_string(),
            fingerprint_digest: "def456".to_string(),
            signed: true,
        })
        .unwrap();

        log.append(AuditEventType::StateTransition {
            key: "my-key".to_string(),
            from_state: "Active".to_string(),
            to_state: "Revoked".to_string(),
            authority: "System".to_string(),
            reason: Some("compromised".to_string()),
        })
        .unwrap();

        assert_eq!(log.len(), 3);

        // Verify chain
        let (count, broken) = log.verify_chain().unwrap();
        assert_eq!(count, 3);
        assert!(broken.is_none());
    }

    #[test]
    fn test_chain_detects_tampering() {
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), "test-node").unwrap();

        log.append(AuditEventType::EntryCreated {
            key: "a".to_string(),
            content_address: "x".to_string(),
            fingerprint_digest: "y".to_string(),
            signed: true,
        })
        .unwrap();

        log.append(AuditEventType::EntryDeleted {
            key: "a".to_string(),
        })
        .unwrap();

        // Tamper: modify the first entry
        let tampered = AuditEntry {
            sequence: 0,
            prev_hash: [0u8; 32],
            hash: [99u8; 32], // wrong hash
            timestamp_ns: 0,
            event: AuditEventType::EntryDeleted {
                key: "TAMPERED".to_string(),
            },
            issuer_id: "attacker".to_string(),
        };
        let tampered_bytes = serde_json::to_vec(&tampered).unwrap();
        log.db.insert(0u64.to_be_bytes(), tampered_bytes).unwrap();

        // Verify detects the break
        let (count, broken) = log.verify_chain().unwrap();
        assert_eq!(count, 0);
        assert_eq!(broken, Some(0));
    }

    #[test]
    fn test_persistence_across_reopens() {
        let dir = tempdir().unwrap();

        // Write entries
        {
            let mut log = AuditLog::open(dir.path(), "node-1").unwrap();
            log.append(AuditEventType::DaemonStart {
                version: "0.3.0".to_string(),
                attest_enabled: true,
                verify_mode: "always".to_string(),
            })
            .unwrap();
            log.append(AuditEventType::EntryCreated {
                key: "k".to_string(),
                content_address: "a".to_string(),
                fingerprint_digest: "f".to_string(),
                signed: true,
            })
            .unwrap();
        }

        // Reopen and verify chain continues
        {
            let mut log = AuditLog::open(dir.path(), "node-1").unwrap();
            assert_eq!(log.len(), 2);

            log.append(AuditEventType::EntryDeleted {
                key: "k".to_string(),
            })
            .unwrap();

            let (count, broken) = log.verify_chain().unwrap();
            assert_eq!(count, 3);
            assert!(broken.is_none());
        }
    }

    #[test]
    fn test_replay_protection() {
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), "test-node").unwrap();

        let nonce = [42u8; 32];

        // First use should succeed
        assert!(log.check_nonce(&nonce));

        // Second use should fail (replay)
        assert!(!log.check_nonce(&nonce));

        // Different nonce should succeed
        let nonce2 = [43u8; 32];
        assert!(log.check_nonce(&nonce2));
    }

    #[test]
    fn test_merkle_anchor() {
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), "test-node").unwrap();

        // Add some entries
        for i in 0..5 {
            log.append(AuditEventType::EntryCreated {
                key: format!("key-{}", i),
                content_address: format!("addr-{}", i),
                fingerprint_digest: format!("fp-{}", i),
                signed: true,
            })
            .unwrap();
        }

        // Compute Merkle anchor
        let root = log.compute_merkle_anchor().unwrap();
        assert_ne!(root, [0u8; 32]);

        // Anchor is recorded in the log (5 entries + 1 MerkleAnchor event)
        assert_eq!(log.len(), 6);

        // Verify chain still valid after anchor
        let (count, broken) = log.verify_chain().unwrap();
        assert!(broken.is_none());
        assert!(count >= 6);
    }

    #[test]
    fn test_export_all() {
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), "test-node").unwrap();

        log.append(AuditEventType::DaemonStart {
            version: "0.3.0".to_string(),
            attest_enabled: true,
            verify_mode: "always".to_string(),
        })
        .unwrap();

        log.append(AuditEventType::EntryCreated {
            key: "k".to_string(),
            content_address: "a".to_string(),
            fingerprint_digest: "f".to_string(),
            signed: true,
        })
        .unwrap();

        let all = log.export_all();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].sequence, 0);
        assert_eq!(all[1].sequence, 1);
    }

    #[test]
    fn test_key_history() {
        let dir = tempdir().unwrap();
        let mut log = AuditLog::open(dir.path(), "test-node").unwrap();

        log.append(AuditEventType::EntryCreated {
            key: "key-a".to_string(),
            content_address: "x".to_string(),
            fingerprint_digest: "y".to_string(),
            signed: true,
        })
        .unwrap();

        log.append(AuditEventType::EntryCreated {
            key: "key-b".to_string(),
            content_address: "x2".to_string(),
            fingerprint_digest: "y2".to_string(),
            signed: true,
        })
        .unwrap();

        log.append(AuditEventType::StateTransition {
            key: "key-a".to_string(),
            from_state: "Active".to_string(),
            to_state: "Revoked".to_string(),
            authority: "System".to_string(),
            reason: Some("test".to_string()),
        })
        .unwrap();

        let history_a = log.key_history("key-a");
        assert_eq!(history_a.len(), 2); // Created + Revoked

        let history_b = log.key_history("key-b");
        assert_eq!(history_b.len(), 1); // Created only
    }
}
