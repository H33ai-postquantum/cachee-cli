//! D-Cachee Federation — cross-instance attestation synchronization
//!
//! Two independent Cachee deployments synchronize archive bundles via
//! DHT-routed replication (FIG 23 from patent specification).
//!
//! These types define the federation API contract. Implementations will
//! be wired in when the federation transport layer ships.

use sha3::{Digest, Sha3_256};

use crate::archive::ComputationType;
use crate::archive::CacheeArchiveBundle;
use crate::archive::H33Primitive;
use crate::keys::KeyType;

// ── Federation Peer ──────────────────────────────────────────────────

/// A node in the D-Cachee federation.
///
/// Each peer maintains its own independent Cachee instance and replicates
/// archive bundles to/from other peers via DHT-routed sync.
#[derive(Debug, Clone)]
pub struct FederationPeer {
    /// Unique identifier for this node (typically SHA3-256 of its public key).
    pub node_id: [u8; 32],
    /// Network endpoint for federation protocol (e.g., `https://peer.example.com:8443`).
    pub endpoint: String,
    /// The peer's ML-DSA-65 public key for authenticating sync messages.
    pub public_key: Vec<u8>,
    /// Unix timestamp (nanoseconds) of the last successful heartbeat from this peer.
    pub last_seen: u64,
}

// ── Sync Request ─────────────────────────────────────────────────────

/// A request to synchronize archive bundles from a peer.
///
/// The requester specifies a timestamp cursor; the responder returns
/// bundles created after that timestamp, up to the requested limit.
#[derive(Debug, Clone)]
pub struct SyncRequest {
    /// Only return bundles created after this timestamp (nanoseconds since epoch).
    pub since_timestamp: u64,
    /// Maximum number of bundles to return in this response.
    pub max_bundles: u32,
    /// The node ID of the requester (for access control and routing).
    pub requester_node_id: [u8; 32],
}

// ── Sync Response ────────────────────────────────────────────────────

/// A response containing archive bundles for federation sync.
///
/// If there are more bundles available beyond this page, `next_cursor`
/// will contain the timestamp to use in the follow-up `SyncRequest`.
#[derive(Debug, Clone)]
pub struct SyncResponse {
    /// The archive bundles being replicated.
    pub bundles: Vec<CacheeArchiveBundle>,
    /// Cursor for the next page, if more bundles are available.
    /// `None` means this is the last page.
    pub next_cursor: Option<u64>,
}

// ── Recipient ────────────────────────────────────────────────────────

/// A recipient of a witness delivery.
///
/// Defines who receives a copy of a bundle and what key type they hold,
/// which determines what they can do with it (verify, query, or decrypt).
#[derive(Debug, Clone)]
pub struct Recipient {
    /// Human-readable name or identifier for the recipient.
    pub name: String,
    /// Network endpoint where the delivery is sent.
    pub endpoint: String,
    /// The recipient's key type, which determines their capability level.
    pub key_type: KeyType,
    /// Current delivery status for this recipient.
    pub delivery_status: DeliveryStatus,
}

// ── Delivery Status ──────────────────────────────────────────────────

/// Status of a witness delivery to a single recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Delivery is queued but not yet attempted.
    Pending,
    /// Delivery was sent and acknowledged by the recipient.
    Delivered,
    /// Delivery attempt failed; will be retried.
    Failed {
        /// Number of retry attempts so far.
        attempts: u32,
        /// Human-readable error from the last attempt.
        last_error: String,
    },
}

// ── Witness Delivery ─────────────────────────────────────────────────

/// A witness delivery: an archive bundle sent to one or more recipients.
///
/// The delivery itself is attested — there is a verifiable record that
/// a specific bundle was delivered to specific parties at a specific time.
#[derive(Debug, Clone)]
pub struct WitnessDelivery {
    /// The archive bundle being delivered.
    pub bundle: CacheeArchiveBundle,
    /// The list of recipients receiving this delivery.
    pub recipients: Vec<Recipient>,
    /// Unix timestamp (nanoseconds) when the delivery was initiated.
    pub delivered_at: u64,
    /// H33Primitive attesting the delivery event itself.
    pub delivery_attestation: H33Primitive,
}

// ── Federation Trust Model (Guarantee #4) ───────────────────────────

/// Trust boundary — who do I accept results from?
///
/// Defines the trust perimeter for a federated Cachee node. Different
/// deployments have different trust requirements: a regulated bank may
/// only trust its own computations, while a public service may accept
/// any independently verifiable result.
#[derive(Debug, Clone)]
pub enum TrustBoundary {
    /// Only accept results I computed myself.
    SelfOnly,
    /// Accept results from explicitly trusted peers.
    TrustedPeers {
        /// SHA3-256 node IDs of trusted peers.
        peer_ids: Vec<[u8; 32]>,
    },
    /// Accept any result that is independently verifiable (signature check).
    AnyVerifiable,
    /// Accept results signed by specific issuers.
    TrustedIssuers {
        /// Public keys of trusted signers.
        issuer_keys: Vec<Vec<u8>>,
    },
}

/// Conflict resolution — two peers, same computation, different results.
///
/// This is a fundamental problem in distributed caching. Unlike Redis
/// (last-write-wins), Cachee can make informed decisions because every
/// result carries provenance and verification signatures.
#[derive(Debug, Clone, PartialEq)]
pub enum ConflictResolution {
    /// Accept the result with the most recent timestamp.
    MostRecent,
    /// Accept the result with the most verification signatures.
    MostVerified,
    /// Reject both and recompute locally.
    RecomputeLocally,
    /// Flag for manual review.
    FlagForReview,
}

/// Federation replication strategy.
///
/// Controls how entries are distributed across D-Cachee federation peers.
/// Full replication is simplest but most expensive. Partial and locality-aware
/// strategies reduce bandwidth and storage costs.
#[derive(Debug, Clone)]
pub enum FederationReplicationStrategy {
    /// Full replication — every peer gets every bundle.
    Full,
    /// Partial — replicate based on computation type or tenant.
    Partial {
        /// Filter defining which entries to replicate.
        filter: FederationReplicationFilter,
    },
    /// Locality-aware — prefer geographically close peers.
    LocalityAware {
        /// Geographic region identifier.
        region: String,
        /// Maximum number of hops for replication.
        max_hops: u8,
    },
}

/// Filter for partial federation replication — which entries get replicated.
#[derive(Debug, Clone)]
pub struct FederationReplicationFilter {
    /// Only replicate entries of these computation types. `None` = all types.
    pub computation_types: Option<Vec<ComputationType>>,
    /// Only replicate entries belonging to these tenants. `None` = all tenants.
    pub tenant_ids: Option<Vec<String>>,
    /// Minimum trust score required for replication.
    pub min_trust_score: f64,
}

// ── Federation Acceptance Rules (Non-Negotiable) ────────────────────

/// Result of a federation bundle acceptance check.
#[derive(Debug, Clone)]
pub enum AcceptanceResult {
    /// Bundle accepted for local storage.
    Accepted,
    /// Bundle rejected with a reason.
    Rejected(String),
}

/// Compute SHA3-256 hash of the given data.
fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Non-negotiable federation acceptance rule.
/// No remote result is accepted unless ALL conditions are met.
pub fn accept_remote_bundle(
    bundle: &CacheeArchiveBundle,
    trust: &TrustBoundary,
    trusted_issuers: &[[u8; 32]],  // SHA3-256 of trusted public keys
) -> AcceptanceResult {
    // Rule 1: Signature must be structurally valid
    let verification = bundle.verify();
    if !verification.valid() && !verification.two_of_three() {
        return AcceptanceResult::Rejected("signature verification failed".into());
    }

    // Rule 2: Fingerprint must be present and non-empty
    if !bundle.has_valid_fingerprint() {
        return AcceptanceResult::Rejected("missing computation fingerprint".into());
    }

    // Rule 3: Issuer must be trusted OR result must be independently verifiable
    let issuer_hash = sha3_256(&bundle.signer_keys.mldsa65);
    let issuer_trusted = trusted_issuers.contains(&issuer_hash);

    match trust {
        TrustBoundary::SelfOnly => {
            return AcceptanceResult::Rejected("self-only mode".into());
        }
        TrustBoundary::TrustedPeers { peer_ids: _ } => {
            if !issuer_trusted {
                return AcceptanceResult::Rejected("issuer not in trusted peers".into());
            }
        }
        TrustBoundary::AnyVerifiable => {
            // Accept if signature valid (already checked above)
        }
        TrustBoundary::TrustedIssuers { issuer_keys: _ } => {
            if !issuer_trusted {
                return AcceptanceResult::Rejected("issuer not in trusted issuers".into());
            }
        }
    }

    AcceptanceResult::Accepted
}
