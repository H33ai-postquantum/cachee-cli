//! Cache invalidation for truth claims, not data.
//!
//! Explicit semantics: superseded, revoked, expired, deprecated.
//! First-class in the storage model, not layered on.
//!
//! Cachee does not cache "data" — it caches *verified computation results*.
//! Invalidation therefore has richer semantics than simple TTL expiry:
//! a result can be superseded by a newer computation, revoked because
//! the signer was compromised, expired because its validity window closed,
//! or deprecated because one of the three PQ families was broken.

use serde::{Deserialize, Serialize};

/// Serde helper for `[u8; 58]` (H33 primitive) — serializes as hex string.
mod serde_bytes_58 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 58], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 58], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 58] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 58 bytes"))?;
        Ok(arr)
    }
}

/// Serde helper for `Option<[u8; 58]>`.
mod serde_option_bytes_58 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 58]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 58]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                let arr: [u8; 58] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 58 bytes"))?;
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

// ── Transition Authority ───────────────────────────────────────────

/// Who is authorized to perform a lifecycle transition.
/// This is non-negotiable — without it, lifecycle is advisory, not authoritative.
#[derive(Debug, Clone)]
pub enum TransitionAuthority {
    /// Only the original issuer (who created the entry) can transition it
    OriginalIssuer { issuer_id: String },
    /// A regulator with a scoped key can transition entries in their scope
    Regulator { key_id: [u8; 32] },
    /// Any party with a valid signature proving they hold the issuer's key
    SignatureBearer,
    /// System-level (expiry, deprecation) — no human authority needed
    System,
}

/// Proof required to perform a transition
#[derive(Debug, Clone)]
pub enum TransitionProof {
    /// No proof — system-initiated (expiry timer, deprecation policy)
    SystemInitiated,
    /// Signature from the original issuer
    IssuerSignature { signature: Vec<u8> },
    /// Regulator key attestation
    RegulatorAttestation { key_id: [u8; 32], attestation: Vec<u8> },
}

/// Whether a transition is reversible
pub fn is_reversible(state: &EntryState) -> bool {
    match state {
        EntryState::Superseded { .. } => false,  // terminal
        EntryState::Revoked { .. } => false,      // terminal
        EntryState::Expired { .. } => true,       // can re-validate
        EntryState::Deprecated { .. } => true,    // can re-attest
        EntryState::Active => true,               // can transition to anything
    }
}

// ── Entry State ─────────────────────────────────────────────────────

/// Cache entry lifecycle state — first-class, not an afterthought.
///
/// Every cached computation result carries an explicit state that determines
/// whether it should be trusted, replaced, or flagged for review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EntryState {
    /// Active and valid — the default state for newly cached results.
    Active,
    /// Superseded by a newer computation (link to successor).
    Superseded {
        /// Content address of the replacement entry.
        successor: [u8; 32],
    },
    /// Revoked — invalid or compromised.
    Revoked {
        /// Human-readable reason for revocation.
        reason: String,
        /// Unix timestamp (nanoseconds) when the entry was revoked.
        revoked_at: u64,
        /// Optional H33 primitive attesting the revocation event.
        #[serde(with = "serde_option_bytes_58")]
        revocation_attestation: Option<[u8; 58]>,
    },
    /// Time-bounded validity expired.
    Expired {
        /// Unix timestamp (nanoseconds) when the entry became invalid.
        valid_until: u64,
    },
    /// Crypto family deprecated — may still be valid under 2-of-3 rule.
    Deprecated {
        /// The PQ family that was deprecated (e.g. "ML-DSA-65", "FALCON-512").
        family: String,
        /// Unix timestamp (nanoseconds) of the deprecation announcement.
        deprecation_date: u64,
        /// Whether the entry is still trustworthy under the 2-of-3 rule.
        two_of_three_valid: bool,
    },
}

// ── Validity Window ─────────────────────────────────────────────────

/// Validity window — when this result is considered trustworthy.
///
/// Every cached result has a temporal scope. Unlike Redis TTL, this is
/// a semantic validity window: the result was computed at a point in time
/// and may only be trusted within a defined interval.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidityWindow {
    /// Unix timestamp (nanoseconds) when the result becomes valid.
    pub valid_from: u64,
    /// Unix timestamp (nanoseconds) when the result expires. `None` = indefinite.
    pub valid_until: Option<u64>,
    /// What triggers revalidation before the window closes.
    pub revalidation_trigger: Option<RevalidationTrigger>,
}

// ── Revalidation Trigger ────────────────────────────────────────────

/// What triggers revalidation of a cached computation result.
///
/// Revalidation is distinct from invalidation: the entry is still
/// considered valid, but should be re-checked proactively.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RevalidationTrigger {
    /// Revalidate after this duration (seconds).
    TimeBased {
        /// Interval in seconds between revalidation checks.
        interval_secs: u64,
    },
    /// Revalidate when upstream state changes.
    StateDependent {
        /// Hash of the upstream state this result depends on.
        state_hash: [u8; 32],
    },
    /// Revalidate on explicit external signal.
    ExternalSignal {
        /// Webhook URL that will trigger revalidation.
        webhook_url: String,
    },
}

// ── Supersession Chain ──────────────────────────────────────────────

/// Supersession chain — full history of a computation result.
///
/// When a result is superseded, the old entry is not deleted. Instead,
/// a chain of supersession records is maintained so that any verifier
/// can trace the full lineage of a result back to its origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupersessionChain {
    /// Content address of the current valid entry.
    pub current: [u8; 32],
    /// Ordered history of all previous entries.
    pub history: Vec<ChainEntry>,
}

/// A single entry in the supersession chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    /// Content address of this historical entry.
    pub content_address: [u8; 32],
    /// Lifecycle state at the time of transition.
    pub state: EntryState,
    /// Unix timestamp (nanoseconds) when the transition occurred.
    pub transitioned_at: u64,
    /// Optional H33 primitive (58 bytes) attesting the transition event.
    #[serde(with = "serde_option_bytes_58")]
    pub attestation: Option<[u8; 58]>,
}

// ── Temporal Binding (Guarantee #10) ────────────────────────────────

/// Temporal binding — results are valid at a point in time, not forever.
///
/// Every cached computation result is bound to a specific moment in time
/// and optionally to the state of an external system (blockchain block
/// height, state root, internal version). This prevents stale results
/// from being served as if they were current.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalBinding {
    /// Unix timestamp (nanoseconds) when the computation was performed.
    pub computed_at: u64,
    /// Optional anchor to an external system's state.
    pub state_anchor: Option<StateAnchor>,
    /// How long the result remains valid.
    pub validity: ValidityWindow,
    /// Whether revalidation is required and when.
    pub revalidation: Option<RevalidationPolicy>,
}

/// External state anchor — binds a result to a specific system state.
///
/// For example, a financial computation might be bound to a specific
/// Ethereum block height, ensuring the result is only valid for that
/// snapshot of on-chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateAnchor {
    /// What system's state this is bound to (e.g., "ethereum", "bitcoin", "internal_state").
    pub system: String,
    /// State identifier (block hash, state root, version number).
    pub state_id: Vec<u8>,
    /// Unix timestamp (nanoseconds) of the anchored state.
    pub state_timestamp: u64,
}

/// Revalidation policy — when and how to revalidate a cached result.
///
/// Distinct from the validity window: the window defines hard expiry,
/// while the revalidation policy defines proactive freshness checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevalidationPolicy {
    /// Maximum age (seconds) before mandatory revalidation.
    pub max_age_secs: u64,
    /// Whether to automatically revalidate or just flag for review.
    pub auto_revalidate: bool,
    /// What triggers revalidation besides age.
    pub triggers: Vec<RevalidationTrigger>,
}
