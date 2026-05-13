//! CacheSlot — the core storage unit. Every value in Cachee carries
//! its full identity, lifecycle state, and trust metadata.
//! This is NOT a key-value pair. This is a computation artifact.

use sha3::{Digest, Sha3_256};

use crate::archive::ComputationFingerprint;
use crate::lifecycle::{
    EntryState, TemporalBinding, TransitionAuthority, TransitionProof, ValidityWindow,
};
use crate::trust::{Provenance, TrustLevel, VerificationMode};

// ── Helpers ────────────────────────────────────────────────────────

/// Return current time as nanoseconds since Unix epoch.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Compute SHA3-256 hash of the given data.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ── Write Conflict Detection ──────────────────────────────────────

/// Conflict detected when a write arrives with a fingerprint that already exists
/// but produces a different result.
pub enum WriteConflict {
    /// No conflict — new fingerprint, or same fingerprint + same result
    None,
    /// Same fingerprint, different result — nondeterminism or bug
    FingerprintCollision {
        existing_address: [u8; 32],
        incoming_hash: [u8; 32],
    },
    /// Same result, different fingerprint — version drift
    ResultDuplicate {
        existing_fingerprint: Box<ComputationFingerprint>,
        incoming_fingerprint: Box<ComputationFingerprint>,
    },
}

/// How to resolve a conflict
pub enum ConflictPolicy {
    /// Reject the write — strictest, safest
    Reject,
    /// Accept as a new entry (fork)
    Fork,
    /// Supersede the existing entry
    Supersede,
}

/// Check for conflicts before writing.
/// Called by the storage layer on every SET.
pub fn detect_conflict(
    existing: Option<&CacheSlot>,
    incoming_value: &[u8],
    incoming_fingerprint: &ComputationFingerprint,
) -> WriteConflict {
    let Some(existing) = existing else {
        return WriteConflict::None;
    };

    let incoming_value_hash = sha3_256(incoming_value);
    let existing_value_hash = sha3_256(&existing.value);

    // Same fingerprint, different result = nondeterminism
    if existing.fingerprint.digest() == incoming_fingerprint.digest()
        && incoming_value_hash != existing_value_hash
    {
        return WriteConflict::FingerprintCollision {
            existing_address: existing.content_address,
            incoming_hash: incoming_value_hash,
        };
    }

    // Same result, different fingerprint = version drift
    if incoming_value_hash == existing_value_hash
        && existing.fingerprint.digest() != incoming_fingerprint.digest()
    {
        return WriteConflict::ResultDuplicate {
            existing_fingerprint: Box::new(existing.fingerprint.clone()),
            incoming_fingerprint: Box::new(incoming_fingerprint.clone()),
        };
    }

    WriteConflict::None
}

// ── CacheSlot ──────────────────────────────────────────────────────

/// The atomic unit of storage in Cachee. Not a key-value pair.
/// A reproducible computation artifact with full identity and trust metadata.
pub struct CacheSlot {
    /// The cached computation result.
    pub value: Vec<u8>,
    /// Deterministic computation identity — what produced this result.
    pub fingerprint: ComputationFingerprint,
    /// When this entry expires (for L0/L1 eviction, NOT lifecycle expiry).
    pub cache_expires_at: std::time::Instant,
    /// Lifecycle state (Active, Superseded, Revoked, Expired, Deprecated).
    pub state: EntryState,
    /// Current trust level and verification history.
    pub trust: TrustLevel,
    /// Temporal binding — when this result is valid.
    pub temporal: TemporalBinding,
    /// Who computed this result, when, where.
    pub provenance: Provenance,
    /// When this slot was created (nanoseconds since Unix epoch).
    pub created_at: u64,
    /// Content address (deterministic from primitive + content_hash + fingerprint).
    pub content_address: [u8; 32],
}

impl CacheSlot {
    /// Create a new CacheSlot. Computes content_address automatically.
    ///
    /// The content address is `SHA3-256(value_hash || fingerprint.digest())`
    /// and serves as the unique, deterministic identity of this computation artifact.
    pub fn new(
        value: Vec<u8>,
        fingerprint: ComputationFingerprint,
        ttl: std::time::Duration,
        verification_mode: VerificationMode,
        node_id: &str,
    ) -> Self {
        let now = now_ns();
        let content_address = Self::compute_content_address(&value, &fingerprint);

        Self {
            fingerprint: fingerprint.clone(),
            cache_expires_at: std::time::Instant::now() + ttl,
            state: EntryState::Active,
            trust: TrustLevel {
                verification_mode,
                last_verified_at: now,
                verification_count: 0,
                signatures_checked: 0,
                trust_score: 1.0,
            },
            temporal: TemporalBinding {
                computed_at: now,
                state_anchor: None,
                validity: ValidityWindow {
                    valid_from: now,
                    valid_until: Some(now + ttl.as_nanos() as u64),
                    revalidation_trigger: None,
                },
                revalidation: None,
            },
            provenance: Provenance {
                computed_by: node_id.to_string(),
                computed_at: now,
                computation_duration_us: 0,
                verified_by: Vec::new(),
            },
            created_at: now,
            content_address,
            value,
        }
    }

    /// Check if this slot's fingerprint is valid (non-empty hashes).
    pub fn has_valid_fingerprint(&self) -> bool {
        self.fingerprint.input_hash != [0u8; 32] && self.fingerprint.computation_hash != [0u8; 32]
    }

    /// Compute content address: SHA3-256(value_hash || fingerprint.digest()).
    fn compute_content_address(value: &[u8], fingerprint: &ComputationFingerprint) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        // First hash the value itself
        let value_hash = {
            let mut h = Sha3_256::new();
            h.update(value);
            h.finalize()
        };
        hasher.update(value_hash);
        hasher.update(fingerprint.digest());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Transition to a new lifecycle state. Returns error if transition is illegal.
    ///
    /// Every transition (except expiry) produces a timestamp record.
    /// Terminal states (Superseded, Revoked) cannot be transitioned out of.
    ///
    /// Authority and proof specify who is performing the transition and
    /// what evidence they carry. System-initiated transitions (expiry,
    /// deprecation) use `TransitionAuthority::System` and
    /// `TransitionProof::SystemInitiated`.
    pub fn transition(
        &mut self,
        new_state: EntryState,
        authority: TransitionAuthority,
        proof: TransitionProof,
    ) -> Result<StateTransition, String> {
        // Validate transition legality
        match (&self.state, &new_state) {
            (EntryState::Active, EntryState::Superseded { .. }) => {}
            (EntryState::Active, EntryState::Revoked { .. }) => {}
            (EntryState::Active, EntryState::Expired { .. }) => {}
            (EntryState::Active, EntryState::Deprecated { .. }) => {}
            (EntryState::Expired { .. }, EntryState::Active) => {} // re-validation
            (EntryState::Deprecated { .. }, EntryState::Active) => {} // re-attestation
            (EntryState::Superseded { .. }, _) => {
                return Err("terminal state: superseded".into());
            }
            (EntryState::Revoked { .. }, _) => {
                return Err("terminal state: revoked".into());
            }
            _ => {
                return Err(format!(
                    "illegal transition: {:?} -> {:?}",
                    self.state, new_state
                ));
            }
        }

        let transition = StateTransition {
            from: self.state.clone(),
            to: new_state.clone(),
            transitioned_at: now_ns(),
            content_address: self.content_address,
            authority,
            proof,
        };

        self.state = new_state;
        Ok(transition)
    }

    /// Check if this entry should be evicted by CacheeLFU.
    ///
    /// Only Active entries are eviction candidates.
    /// Non-Active entries are retained until explicit archival.
    pub fn is_evictable(&self) -> bool {
        matches!(self.state, EntryState::Active)
    }
}

// ── StateTransition ────────────────────────────────────────────────

/// Record of a lifecycle state transition on a CacheSlot.
///
/// Every transition produces one of these, providing a full audit trail
/// of state changes with nanosecond timestamps and content addresses.
#[derive(Debug)]
pub struct StateTransition {
    /// The state the slot was in before the transition.
    pub from: EntryState,
    /// The state the slot transitioned to.
    pub to: EntryState,
    /// Unix timestamp (nanoseconds) when the transition occurred.
    pub transitioned_at: u64,
    /// Content address of the slot that was transitioned.
    pub content_address: [u8; 32],
    /// Who authorized this transition.
    pub authority: TransitionAuthority,
    /// Proof backing the transition authority.
    pub proof: TransitionProof,
}

// ── Parse helpers for RESP fingerprint argument ────────────────────

/// Parse a hex-encoded fingerprint string into a ComputationFingerprint.
///
/// Expected format: 192 hex characters (96 bytes) = input_hash(32) + computation_hash(32) + parameter_hash(32).
/// If the hex is malformed or too short, returns an empty fingerprint.
pub fn parse_fingerprint(hex_str: &str) -> ComputationFingerprint {
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return ComputationFingerprint::empty(),
    };

    if bytes.len() < 96 {
        return ComputationFingerprint::empty();
    }

    let mut input_hash = [0u8; 32];
    let mut computation_hash = [0u8; 32];
    let mut parameter_hash = [0u8; 32];
    input_hash.copy_from_slice(&bytes[0..32]);
    computation_hash.copy_from_slice(&bytes[32..64]);
    parameter_hash.copy_from_slice(&bytes[64..96]);

    ComputationFingerprint {
        input_hash,
        computation_hash,
        parameter_hash,
        version: crate::archive::ComputationVersion {
            engine: "cachee-cli".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            circuit_id: None,
        },
        hardware_class: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_slot_is_active() {
        let slot = CacheSlot::new(
            b"test-value".to_vec(),
            ComputationFingerprint::empty(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "test-node",
        );
        assert!(matches!(slot.state, EntryState::Active));
        assert!(slot.is_evictable());
    }

    #[test]
    fn test_empty_fingerprint_is_invalid() {
        let slot = CacheSlot::new(
            b"test-value".to_vec(),
            ComputationFingerprint::empty(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "test-node",
        );
        assert!(!slot.has_valid_fingerprint());
    }

    #[test]
    fn test_transition_active_to_revoked() {
        let mut slot = CacheSlot::new(
            b"test".to_vec(),
            ComputationFingerprint::empty(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "node-1",
        );
        let result = slot.transition(
            EntryState::Revoked {
                reason: "compromised".to_string(),
                revoked_at: 123,
                revocation_attestation: None,
            },
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        );
        assert!(result.is_ok());
        assert!(!slot.is_evictable());
    }

    #[test]
    fn test_terminal_state_superseded() {
        let mut slot = CacheSlot::new(
            b"test".to_vec(),
            ComputationFingerprint::empty(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "node-1",
        );
        slot.transition(
            EntryState::Superseded {
                successor: [1u8; 32],
            },
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        )
        .unwrap();
        let result = slot.transition(
            EntryState::Active,
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("terminal state"));
    }

    #[test]
    fn test_terminal_state_revoked() {
        let mut slot = CacheSlot::new(
            b"test".to_vec(),
            ComputationFingerprint::empty(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "node-1",
        );
        slot.transition(
            EntryState::Revoked {
                reason: "test".to_string(),
                revoked_at: 0,
                revocation_attestation: None,
            },
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        )
        .unwrap();
        let result = slot.transition(
            EntryState::Active,
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_expired_can_revalidate() {
        let mut slot = CacheSlot::new(
            b"test".to_vec(),
            ComputationFingerprint::empty(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "node-1",
        );
        slot.transition(
            EntryState::Expired { valid_until: 100 },
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        )
        .unwrap();
        let result = slot.transition(
            EntryState::Active,
            TransitionAuthority::System,
            TransitionProof::SystemInitiated,
        );
        assert!(result.is_ok());
        assert!(slot.is_evictable());
    }

    #[test]
    fn test_content_address_determinism() {
        let value = b"deterministic-test".to_vec();
        let fp = ComputationFingerprint::empty();
        let slot1 = CacheSlot::new(
            value.clone(),
            fp.clone(),
            std::time::Duration::from_secs(60),
            VerificationMode::TrustCached,
            "node-1",
        );
        let slot2 = CacheSlot::new(
            value,
            fp,
            std::time::Duration::from_secs(120),
            VerificationMode::AlwaysVerify,
            "node-2",
        );
        assert_eq!(slot1.content_address, slot2.content_address);
    }

    #[test]
    fn test_parse_fingerprint_valid() {
        let hex = "aa".repeat(96);
        let fp = parse_fingerprint(&hex);
        assert_eq!(fp.input_hash, [0xaa; 32]);
        assert_eq!(fp.computation_hash, [0xaa; 32]);
        assert_eq!(fp.parameter_hash, [0xaa; 32]);
    }

    #[test]
    fn test_parse_fingerprint_invalid() {
        let fp = parse_fingerprint("not-hex");
        assert_eq!(fp.input_hash, [0u8; 32]);
    }
}
