//! Trust observability — not just performance metrics.
//!
//! The killer metric: "% of computation avoided". This is what sells Cachee.
//! Redis can tell you hit rate. Cachee can tell you how much computation
//! you did NOT have to redo, how much that saved in dollars, and how
//! trustworthy every served result was.

// ── Cachee Metrics ──────────────────────────────────────────────────

/// Trust-aware metrics — what matters for a verifiable cache.
///
/// Standard cache metrics (hit rate, latency) plus trust metrics
/// (verification rate, computation savings) plus lifecycle metrics
/// (how many entries are active vs. revoked) plus federation metrics.
#[derive(Debug, Clone, Default)]
pub struct CacheeMetrics {
    // ── Standard cache metrics ──────────────────────────
    /// Total number of read operations since startup.
    pub total_reads: u64,
    /// Total number of write operations since startup.
    pub total_writes: u64,
    /// Cache hit rate (0.0 to 1.0).
    pub hit_rate: f64,
    /// Cache miss rate (0.0 to 1.0).
    pub miss_rate: f64,
    /// Median read latency in nanoseconds.
    pub latency_p50_ns: u64,
    /// 99th percentile read latency in nanoseconds.
    pub latency_p99_ns: u64,

    // ── Trust metrics (what makes this not Redis) ───────
    /// Fraction of reads that triggered full signature verification.
    pub verification_rate: f64,
    /// Fraction of computation results served from cache (THE KILLER METRIC).
    pub cache_reuse_rate: f64,
    /// Total number of computations NOT re-run because the cached result was trusted.
    pub recomputation_avoided: u64,
    /// Total microseconds of computation time saved by serving cached results.
    pub computation_time_saved_us: u64,
    /// Distribution of trust levels across all served results.
    pub trust_level_distribution: TrustDistribution,

    // ── Lifecycle metrics ───────────────────────────────
    /// Number of entries currently in `Active` state.
    pub active_entries: u64,
    /// Number of entries in `Superseded` state.
    pub superseded_entries: u64,
    /// Number of entries in `Revoked` state.
    pub revoked_entries: u64,
    /// Number of entries in `Expired` state.
    pub expired_entries: u64,
    /// Number of entries in `Deprecated` state.
    pub deprecated_entries: u64,

    // ── Federation metrics ──────────────────────────────
    /// Total reads served from federated peers.
    pub federated_reads: u64,
    /// Total writes replicated to federated peers.
    pub federated_writes: u64,
    /// Total cross-peer signature verifications performed.
    pub cross_peer_verifications: u64,
    /// Number of federation conflicts detected (same computation, different results).
    pub conflict_count: u64,

    // ── Storage tier metrics ────────────────────────────
    /// Number of entries in L1 (in-memory).
    pub l1_entries: u64,
    /// Number of entries in L2 (local persistent).
    pub l2_entries: u64,
    /// Number of entries in L3 (object storage).
    pub l3_entries: u64,
    /// Number of entries in L4 (archival CAB bundles).
    pub l4_entries: u64,
    /// Total storage consumed across all tiers in bytes.
    pub total_storage_bytes: u64,
    /// Number of entries exported to archival tier.
    pub archival_exports: u64,

    // ── Economic metrics ───────────────────────────────
    /// Economic impact metrics — computation savings translated to dollars.
    pub economic: EconomicMetrics,
}

// ── Economic Metrics ────────────────────────────────────────────────

/// Economic metrics — turns "cool system" into budget justification
#[derive(Debug, Clone, Default)]
pub struct EconomicMetrics {
    /// Estimated dollars saved from avoided computation
    pub dollars_saved: f64,
    /// Estimated dollars saved per operation class
    pub savings_by_type: Vec<(String, f64)>,  // (computation_type, dollars_saved)
    /// Average latency saved per cache hit (microseconds)
    pub avg_latency_saved_us: f64,
    /// Total verification cost avoided (ZK/STARK verifications not re-run)
    pub verification_cost_avoided: f64,
    /// Cost per attestation stored
    pub cost_per_attestation: f64,
    /// Projected monthly savings at current rate
    pub projected_monthly_savings: f64,
}

// ── Trust Distribution ──────────────────────────────────────────────

/// Distribution of trust levels across served results.
///
/// Tells operators what fraction of reads were fully verified vs.
/// served from cached verification vs. unverified (probabilistic pass).
#[derive(Debug, Clone, Default)]
pub struct TrustDistribution {
    /// Number of reads where all 3 PQ signatures were verified.
    pub fully_verified: u64,
    /// Number of reads where a cached verification result was used.
    pub cached_verification: u64,
    /// Number of reads that passed probabilistic sampling without verification.
    pub probabilistic_pass: u64,
    /// Number of reads served without any verification.
    pub unverified: u64,
}

// ── Computation Savings Report ──────────────────────────────────────

/// The number that sells: "We eliminated X% of your computation."
///
/// This report summarizes how much computation was avoided over a
/// time period, translated into wall-clock time and estimated dollar cost.
/// This is the metric that makes Cachee's value proposition concrete.
#[derive(Debug, Clone)]
pub struct ComputationSavingsReport {
    /// Start of the reporting period (Unix nanoseconds).
    pub period_start: u64,
    /// End of the reporting period (Unix nanoseconds).
    pub period_end: u64,
    /// Total number of requests during the period.
    pub total_requests: u64,
    /// Number of requests served from cache (computation avoided).
    pub cache_hits: u64,
    /// Percentage of computation avoided (0.0 to 100.0) — THE metric.
    pub computation_avoided_pct: f64,
    /// Estimated compute cost saved in dollars.
    pub estimated_compute_cost_saved: f64,
    /// Estimated wall-clock time saved in seconds.
    pub estimated_time_saved_secs: f64,
}
