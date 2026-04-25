//! Read-path trust contract — every read returns value, computation fingerprint,
//! verification status, signatures, and provenance.
//!
//! This is what makes Cachee not Redis, not just a cache, but a verifiable system.
//! A Redis GET returns bytes. A Cachee read returns bytes + cryptographic proof
//! of correctness + full provenance + lifecycle state. The consumer always knows
//! exactly what they are trusting and why.

use serde::{Deserialize, Serialize};

use crate::archive::ComputationFingerprint;
use crate::lifecycle::{EntryState, ValidityWindow};
use crate::trust::Provenance;

// ── Verification Status ─────────────────────────────────────────────

/// Verification status on a specific read — did we actually check the signatures?
///
/// Not every read triggers full PQ signature verification (that would be
/// too expensive at 39,083x speedup). This enum tells the consumer exactly
/// what level of verification was performed on *this specific read*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// All three PQ signatures were verified on this read.
    FullyVerified {
        /// Unix timestamp (nanoseconds) when verification completed.
        checked_at: u64,
    },
    /// Verification result was cached from a previous read.
    CachedVerification {
        /// Unix timestamp (nanoseconds) of the original verification.
        originally_verified_at: u64,
        /// How many seconds ago the original verification occurred.
        age_secs: u64,
    },
    /// This read was not selected for verification (probabilistic mode).
    Unverified {
        /// Unix timestamp (nanoseconds) of the most recent verification.
        last_verified_at: u64,
        /// Current trust score based on verification history.
        trust_score: f64,
    },
}

// ── Signature Summary ───────────────────────────────────────────────

/// Summary of PQ signature status — not the full signatures, just validity flags.
///
/// Full signatures are only returned when explicitly requested (they are
/// large: ~21 KB total). The summary tells the consumer which families
/// are valid without the overhead of transmitting the signatures themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSummary {
    /// ML-DSA-65 (Dilithium) signature validity. `None` = not checked on this read.
    pub mldsa_valid: Option<bool>,
    /// FALCON-512 signature validity. `None` = not checked on this read.
    pub falcon_valid: Option<bool>,
    /// SLH-DSA-SHA2-128f (SPHINCS+) signature validity. `None` = not checked on this read.
    pub slhdsa_valid: Option<bool>,
    /// Whether at least 2 of 3 families are valid (the minimum trust threshold).
    pub two_of_three: bool,
    /// Unix timestamp (nanoseconds) of the last time all three families were checked.
    pub last_full_check: u64,
}

// ── Cachee Read Response ────────────────────────────────────────────

/// The read response contract — what Cachee returns on every GET.
///
/// This is the full trust envelope around a cached value. A consumer
/// receiving this response has everything needed to make an informed
/// trust decision without any additional network calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheeReadResponse {
    /// The cached value bytes.
    pub value: Vec<u8>,
    /// Full computation identity (what produced this result).
    pub fingerprint: ComputationFingerprint,
    /// Verification status for this specific read.
    pub verification: VerificationStatus,
    /// Signature summary (not full sigs unless requested).
    pub signatures: SignatureSummary,
    /// Who computed this, when, where.
    pub provenance: Provenance,
    /// Current lifecycle state (active, superseded, revoked, etc.).
    pub state: EntryState,
    /// Validity window for this result.
    pub validity: ValidityWindow,
}
