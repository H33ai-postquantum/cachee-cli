//! Verification cost model — three modes: always verify, trust cached, probabilistic.
//!
//! Configurable per tenant, per entry class, per policy.
//! This is the layer that makes Cachee a *verifiable* system, not just a fast one.
//! Every read can optionally carry proof of correctness — the cost of that
//! proof is configurable based on the security posture of the consumer.

use serde::{Deserialize, Serialize};

use crate::archive::ComputationFingerprint;
use crate::lifecycle::EntryState;

// ── Verification Mode ───────────────────────────────────────────────

/// How aggressively to verify cached results on read.
///
/// Regulators and courts want `AlwaysVerify`. Internal hot paths want
/// `TrustCached`. Everything in between uses `Probabilistic` or `AgeWeighted`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Always re-verify signatures on every read (cold path, regulators).
    AlwaysVerify,
    /// Trust the cached verification result (hot path, internal).
    TrustCached,
    /// Re-verify probabilistically based on policy.
    Probabilistic {
        /// Fraction of reads that trigger full verification (0.0 to 1.0).
        sample_rate: f64,
    },
    /// Re-verify based on age — older results get verified more often.
    AgeWeighted {
        /// Maximum age (seconds) before every read triggers verification.
        max_age_before_reverify_secs: u64,
    },
}

// ── Trust Level ─────────────────────────────────────────────────────

/// Per-entry trust level — returned on every read.
///
/// This is the quantified trustworthiness of a cached result at the
/// moment it is served. Consumers can use this to make risk decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustLevel {
    /// The verification mode that was active when this trust level was computed.
    pub verification_mode: VerificationMode,
    /// Unix timestamp (nanoseconds) of the last full signature verification.
    pub last_verified_at: u64,
    /// Total number of times this entry has been verified since creation.
    pub verification_count: u64,
    /// How many of the 3 PQ families were checked (0-3).
    pub signatures_checked: u8,
    /// Computed trust score (0.0 to 1.0) based on mode, age, and family status.
    pub trust_score: f64,
}

// ── Verified Read ───────────────────────────────────────────────────

/// Read-path trust contract — what every read returns.
///
/// This is the fundamental difference between Cachee and a regular cache:
/// every read carries provenance, verification status, and lifecycle state.
/// The consumer always knows *what* they got, *who* computed it, *when*,
/// and *how trustworthy* the result is right now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedRead<T> {
    /// The cached computation result.
    pub value: T,
    /// Current trust assessment.
    pub trust_level: TrustLevel,
    /// Full computation identity (what produced this result).
    pub computation_fingerprint: ComputationFingerprint,
    /// Current lifecycle state (active, superseded, revoked, etc.).
    pub entry_state: EntryState,
    /// Who computed this result and when.
    pub provenance: Provenance,
}

// ── Provenance ──────────────────────────────────────────────────────

// ── Policy Enforcement ─────────────────────────────────────────────

/// Verification mode ordering (strictness level).
/// Higher number = stricter.
pub fn mode_strictness(mode: &str) -> u8 {
    match mode {
        "trust_cached" => 1,
        "probabilistic" => 2,
        "age_weighted" => 3,
        "always_verify" => 4,
        _ => 0,
    }
}

/// Check if a mode change is allowed under the current policy.
pub fn is_mode_change_allowed(
    current: &str,
    proposed: &str,
    locked: bool,
    minimum: Option<&str>,
) -> Result<(), String> {
    if locked && mode_strictness(proposed) < mode_strictness(current) {
        return Err(format!(
            "Verification mode is locked. Cannot downgrade from '{}' to '{}'. Only upgrades allowed.",
            current, proposed
        ));
    }
    if let Some(min) = minimum {
        if mode_strictness(proposed) < mode_strictness(min) {
            return Err(format!(
                "Minimum verification mode is '{}'. Cannot set '{}'.",
                min, proposed
            ));
        }
    }
    Ok(())
}

// ── Provenance ──────────────────────────────────────────────────────

/// Who computed this result, when, how long it took, and who has verified it.
///
/// Provenance is immutable once recorded. It forms part of the
/// computation's identity and is included in attestation hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    /// Node ID or tenant ID that performed the original computation.
    pub computed_by: String,
    /// Unix timestamp (nanoseconds) when the computation completed.
    pub computed_at: u64,
    /// Wall-clock duration of the original computation in microseconds.
    pub computation_duration_us: u64,
    /// Node IDs that have independently verified this result.
    pub verified_by: Vec<String>,
}
