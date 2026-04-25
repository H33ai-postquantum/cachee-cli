//! Multi-tier storage strategy: L1 (memory) -> L2 (local) -> L3 (object) -> L4 (archival).
//!
//! Routing between tiers is performance-critical and cost-critical.
//! L1 serves at 31ns (in-process DashMap). L4 produces independently
//! verifiable CAB bundles. The tier policy controls promotion, demotion,
//! and archival scheduling — all transitions are themselves attested.

// ── Storage Consistency Guarantees ──────────────────────────────────

/// Write behavior across tiers
#[derive(Debug, Clone)]
pub enum WriteBehavior {
    /// Write to L1 only — fastest, least durable (crash = data loss)
    WriteL1Only,
    /// Write to L1 + L2 synchronously — durable, slightly slower
    WriteThrough,
    /// Write to L1 immediately, async flush to L2 — fast, eventually durable
    WriteBack { flush_interval_ms: u64 },
}

/// Durability guarantee per tier
#[derive(Debug, Clone)]
pub enum DurabilityGuarantee {
    /// No durability — in-memory only (L1)
    None,
    /// Local disk persistence (L2)
    LocalDisk,
    /// Replicated to object storage (L3)
    ObjectStorage,
    /// Exported as CAB bundle — independently verifiable (L4)
    Archival,
}

/// What happens when a tier write fails
#[derive(Debug, Clone)]
pub enum FailurePolicy {
    /// Fail the entire write — no partial state
    FailAll,
    /// Succeed at higher tier, retry lower tier asynchronously
    BestEffort { retry_count: u8, retry_delay_ms: u64 },
    /// Log the failure and continue — tier will be inconsistent until rebuild
    LogAndContinue,
}

/// Rebuild strategy — how to recover from tier inconsistency
#[derive(Debug, Clone)]
pub enum RebuildStrategy {
    /// Rebuild lower tier from upper tier (L2 from L1)
    TopDown,
    /// Rebuild upper tier from lower tier (L1 from L2) — used on cold start
    BottomUp,
    /// Full rebuild from L4 archival bundles
    FromArchive,
}

// ── Storage Tier ────────────────────────────────────────────────────

/// Storage tier — where a cached entry physically resides.
///
/// Each tier trades latency for durability and cost. Entries flow
/// downward (L1 -> L4) based on age and access frequency, and
/// are promoted upward on access if configured.
#[derive(Debug, Clone, PartialEq)]
pub enum StorageTier {
    /// In-memory, ultra-fast (31ns reads via DashMap).
    L1Memory,
    /// Local persistent (SSD-backed, microsecond reads).
    L2Local,
    /// Object storage (S3/Azure/GCS, millisecond reads).
    L3Object {
        /// Which object storage provider hosts this tier.
        provider: ObjectProvider,
    },
    /// Archival (CAB bundles, exported, independently verifiable).
    L4Archival,
}

// ── Object Provider ─────────────────────────────────────────────────

/// Supported object storage providers for L3 tier.
#[derive(Debug, Clone, PartialEq)]
pub enum ObjectProvider {
    /// Amazon S3.
    S3 {
        /// S3 bucket name.
        bucket: String,
        /// AWS region (e.g., "us-east-1").
        region: String,
    },
    /// Azure Blob Storage.
    Azure {
        /// Azure container name.
        container: String,
    },
    /// Google Cloud Storage.
    Gcs {
        /// GCS bucket name.
        bucket: String,
    },
    /// Local filesystem (for development and testing).
    Local {
        /// Filesystem path for local object storage.
        path: String,
    },
}

// ── Tier Policy ─────────────────────────────────────────────────────

/// Tier routing policy — what goes where and when.
///
/// Controls the lifecycle of entries across storage tiers. Entries
/// start in L1 (hot) and flow toward L4 (cold/archival) based on
/// age, size, and access patterns.
#[derive(Debug, Clone)]
pub struct TierPolicy {
    /// Maximum age (seconds) an entry stays in L1 before demotion to L2.
    pub l1_max_age_secs: u64,
    /// Maximum age (seconds) an entry stays in L2 before demotion to L3.
    pub l2_max_age_secs: u64,
    /// Age (seconds) after which an entry is exported to L4 archival.
    pub archival_after_secs: u64,
    /// Maximum value size (bytes) for L1 — larger values skip directly to L2.
    pub l1_max_value_bytes: usize,
    /// Whether to promote entries from lower tiers on access (read-through).
    pub promote_on_access: bool,
}

// ── Tier Transition ─────────────────────────────────────────────────

/// A tier transition event — itself attested.
///
/// Every movement of an entry between tiers is recorded with a timestamp
/// and reason. This provides a full audit trail of where data has been
/// stored and why it was moved.
#[derive(Debug, Clone)]
pub struct TierTransition {
    /// Content address of the entry that was moved.
    pub content_address: [u8; 32],
    /// The tier the entry was in before the transition.
    pub from_tier: StorageTier,
    /// The tier the entry moved to.
    pub to_tier: StorageTier,
    /// Unix timestamp (nanoseconds) when the transition occurred.
    pub transitioned_at: u64,
    /// Why the transition happened.
    pub reason: TransitionReason,
}

// ── Transition Reason ───────────────────────────────────────────────

/// Why a tier transition occurred.
#[derive(Debug, Clone, PartialEq)]
pub enum TransitionReason {
    /// Entry exceeded the maximum age for its current tier.
    AgePolicy,
    /// Entry exceeded the maximum size for its current tier.
    SizePolicy,
    /// Entry's access frequency dropped below the promotion threshold.
    AccessFrequency,
    /// Entry was explicitly exported by the user.
    ExplicitExport,
    /// Scheduled cold storage sweep moved the entry.
    ColdStorageSchedule,
}

// ── Replication Strategy ────────────────────────────────────────────

/// Replication strategy for federated entries.
///
/// Controls how entries are distributed across D-Cachee federation peers.
/// Full replication is simplest but most expensive. Partial and locality-aware
/// strategies reduce bandwidth and storage costs.
#[derive(Debug, Clone)]
pub enum ReplicationStrategy {
    /// Full replication — every peer gets every bundle.
    Full,
    /// Partial — replicate based on computation type or tenant.
    Partial {
        /// Filter defining which entries to replicate.
        filter: ReplicationFilter,
    },
    /// Locality-aware — prefer geographically close peers.
    LocalityAware {
        /// Geographic region identifier.
        region: String,
        /// Maximum number of hops for replication.
        max_hops: u8,
    },
}

// ── Replication Filter ──────────────────────────────────────────────

/// Filter for partial replication — which entries get replicated.
#[derive(Debug, Clone)]
pub struct ReplicationFilter {
    /// Only replicate entries of these computation types. `None` = all types.
    pub computation_types: Option<Vec<crate::archive::ComputationType>>,
    /// Only replicate entries belonging to these tenants. `None` = all tenants.
    pub tenant_ids: Option<Vec<String>>,
    /// Minimum trust score required for replication.
    pub min_trust_score: f64,
}
