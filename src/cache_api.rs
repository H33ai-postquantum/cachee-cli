//! Explicit caching API — developers control what gets cached and how.
//!
//! No implicit caching. No ambiguity. Every cache operation is deliberate,
//! every policy is declared upfront, and every result carries a receipt
//! proving what was stored, when, and with what attestation level.
//!
//! This is the developer-facing surface of Cachee's guarantee system.
//! The builder pattern makes it impossible to accidentally cache without
//! specifying verification, validity, and scope.

use crate::archive::ComputationFingerprint;
use crate::lifecycle::ValidityWindow;
use crate::read_contract::CacheeReadResponse;
use crate::storage::{ReplicationStrategy, StorageTier};
use crate::trust::VerificationMode;

// ── Cache Entry ─────────────────────────────────────────────────────

/// A computation result to be cached, with full policy declaration.
///
/// Built via the builder pattern to ensure all required fields are
/// specified before caching. No implicit defaults for critical policy.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// Cache key — the lookup identifier.
    pub key: String,
    /// The computation result bytes to cache.
    pub value: Vec<u8>,
    /// Full computation identity (what produced this result).
    pub fingerprint: ComputationFingerprint,
    /// Caching policy (verification, validity, scope, attestation).
    pub policy: CachePolicy,
}

// ── Cache Policy ────────────────────────────────────────────────────

/// Complete caching policy — declares how this entry should be treated.
///
/// Every aspect of the entry's lifecycle is specified upfront:
/// how it should be verified on read, how long it is valid,
/// where it should be stored, and whether it needs attestation.
#[derive(Debug, Clone)]
pub struct CachePolicy {
    /// How to verify this entry when read.
    pub verification_mode: VerificationMode,
    /// When this entry is considered valid.
    pub validity: ValidityWindow,
    /// Where this entry is visible (local, federated, archival).
    pub scope: CacheScope,
    /// Whether and how to attest this entry.
    pub attestation: AttestationPolicy,
}

// ── Cache Scope ─────────────────────────────────────────────────────

/// Visibility scope — where this cached entry is accessible.
///
/// Controls whether a result stays on a single node, replicates
/// across the federation, or is exported as an archival CAB bundle.
#[derive(Debug, Clone)]
pub enum CacheScope {
    /// Local to this instance only — fastest, no replication overhead.
    Local,
    /// Shared across federated D-Cachee instances.
    Federated {
        /// How to replicate across the federation.
        replication: ReplicationStrategy,
    },
    /// Exportable as a Cachee Archive Bundle (CAB) file.
    Archival,
}

// ── Attestation Policy ──────────────────────────────────────────────

/// Whether and how to attest a cached entry with H33-74 signatures.
///
/// Full attestation adds ~26ms (SPHINCS+-dominated) but provides
/// three-family PQ proof. `OnDemand` defers attestation until a
/// read actually requires it.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestationPolicy {
    /// No attestation (fastest, no crypto overhead).
    None,
    /// Attest with H33-74 (3-family PQ signature) at cache time.
    Full,
    /// Attest only when a read requires verified proof.
    OnDemand,
}

// ── Cachee Store Trait ──────────────────────────────────────────────

/// The explicit caching API — no ambiguity about what gets cached.
///
/// Every method has clear semantics:
/// - `cache_verified`: store a result that has already been verified
/// - `cache_if_verified`: store only if independent verification passes
/// - `cache_with_proof`: store with an attached ZK proof
/// - `read_verified`: read with full trust contract
/// - `invalidate`: explicitly invalidate with a reason
/// - `supersede`: replace an old result with a new one, maintaining the chain
pub trait CacheeStore {
    /// Cache a verified computation result.
    ///
    /// The caller asserts that the result has been verified. The entry
    /// is stored with the declared policy and a receipt is returned.
    fn cache_verified(&self, entry: CacheEntry) -> anyhow::Result<CacheReceipt>;

    /// Cache only if independently verified first.
    ///
    /// Cachee will verify the computation fingerprint and signatures
    /// before storing. Returns `None` if verification fails.
    fn cache_if_verified(&self, entry: CacheEntry) -> anyhow::Result<Option<CacheReceipt>>;

    /// Cache with a full ZK proof attached.
    ///
    /// The proof bytes are stored alongside the value and can be
    /// independently verified by any reader.
    fn cache_with_proof(&self, entry: CacheEntry, proof: Vec<u8>) -> anyhow::Result<CacheReceipt>;

    /// Read with full trust contract.
    ///
    /// Returns the value plus verification status, provenance, lifecycle
    /// state, and validity window. Returns `None` if the key does not exist.
    fn read_verified(&self, key: &str) -> anyhow::Result<Option<CacheeReadResponse>>;

    /// Explicitly invalidate a cached entry.
    ///
    /// The entry is not deleted — its state is transitioned and the
    /// invalidation event is recorded in the supersession chain.
    fn invalidate(&self, key: &str, reason: InvalidationReason) -> anyhow::Result<()>;

    /// Supersede an old result with a new one.
    ///
    /// The old entry's state transitions to `Superseded` with a link
    /// to the new entry. The supersession chain is extended.
    fn supersede(&self, old_key: &str, new_entry: CacheEntry) -> anyhow::Result<CacheReceipt>;
}

// ── Cache Receipt ───────────────────────────────────────────────────

/// Proof that an entry was successfully cached.
///
/// Every cache write returns a receipt that includes the content address,
/// optional attestation, timestamp, and storage tier. The receipt itself
/// can be used as evidence that a specific result was cached at a specific
/// time.
#[derive(Debug, Clone)]
pub struct CacheReceipt {
    /// SHA3-256 content address of the cached entry.
    pub content_address: [u8; 32],
    /// Optional H33 primitive (58 bytes) attesting the cache operation.
    pub attestation: Option<[u8; 58]>,
    /// Unix timestamp (nanoseconds) when the entry was stored.
    pub stored_at: u64,
    /// Which storage tier the entry was placed in.
    pub tier: StorageTier,
}

// ── Invalidation Reason ─────────────────────────────────────────────

/// Why an entry is being invalidated — explicit, auditable reasons.
///
/// Every invalidation must specify a reason. There is no silent deletion.
/// This creates an audit trail for every state transition.
#[derive(Debug, Clone)]
pub enum InvalidationReason {
    /// Replaced by a newer computation result.
    Superseded {
        /// Content address of the successor entry.
        successor_address: [u8; 32],
    },
    /// Revoked due to compromise or error.
    Revoked {
        /// Human-readable reason for revocation.
        reason: String,
    },
    /// Time-bounded validity has expired.
    Expired,
    /// One of the PQ signature families has been deprecated.
    FamilyDeprecated {
        /// The deprecated PQ family name.
        family: String,
    },
}
