//! Cachee Key Types — Owner, Regulator, Auditor
//!
//! Three distinct key types with different capabilities:
//! - Owner: full access, can decrypt
//! - Regulator: scoped ZK query capability, cannot decrypt
//! - Auditor: read-only proof verification, cannot query or decrypt
//!
//! Regulator keys are themselves attested via H33 Substrate — the act of
//! issuing a scoped key produces an H33Primitive, creating an immutable
//! audit trail of who was granted what access and when.

use crate::archive::H33Primitive;

// ── ZK Query Model (Guarantee #7) ───────────────────────────────────

/// Query model — defines what is queryable BEFORE building circuits.
///
/// This is the schema layer that sits between the cached data and the
/// ZK circuit layer. It declares which fields can be queried, what
/// comparison operations are supported, and what constraints apply.
/// Circuit design flows from this model, not the other way around.
#[derive(Debug, Clone)]
pub struct QueryModel {
    /// What fields in the cached data are queryable.
    pub queryable_fields: Vec<QueryableField>,
    /// What constraints apply to queries.
    pub constraints: Vec<QueryConstraint>,
    /// Maximum proof size in bytes (affects circuit design).
    pub max_proof_size_bytes: usize,
}

/// A single queryable field in the cached data.
#[derive(Debug, Clone)]
pub struct QueryableField {
    /// Field name (e.g., "balance", "exposure_flag", "temperature").
    pub name: String,
    /// The data type of the field.
    pub field_type: FieldType,
    /// Supported comparison operations for this field.
    pub comparison_ops: Vec<ComparisonOp>,
}

/// Data type of a queryable field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// Integer value (mapped to field elements in the STARK circuit).
    Integer,
    /// Boolean value (0 or 1 in the circuit).
    Boolean,
    /// Fixed-size byte array (e.g., hash, address).
    FixedBytes(usize),
    /// Numeric value with a threshold limit.
    Threshold,
}

/// Comparison operation supported by a queryable field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonOp {
    /// Exact equality check.
    Equals,
    /// Less-than comparison.
    LessThan,
    /// Greater-than comparison.
    GreaterThan,
    /// Range inclusion check (value within [min, max]).
    InRange,
    /// Threshold comparison (value >= limit).
    MeetsThreshold,
}

/// Constraints on query complexity.
#[derive(Debug, Clone)]
pub struct QueryConstraint {
    /// Maximum number of fields per query.
    pub max_fields: usize,
    /// Maximum result complexity (affects proof generation time).
    pub max_complexity: usize,
    /// Whether the query itself is attested with H33-74.
    pub attest_query: bool,
}

// ── Query Types ──────────────────────────────────────────────────────

/// The types of zero-knowledge queries a regulator key can execute.
///
/// Each query type corresponds to a specific STARK circuit that proves
/// an answer without revealing the underlying data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryType {
    /// Anti-money-laundering exposure check (yes/no, no amounts revealed).
    AmlExposureCheck,
    /// Aggregate compliance score (numeric, no individual records revealed).
    ComplianceScore,
    /// Supply-chain temperature compliance (within bounds, no raw readings).
    TemperatureCompliance,
    /// Collateral adequacy check (sufficient/insufficient, no portfolio details).
    CollateralAdequacy,
    /// AI model bias metric (score, no training data revealed).
    BiasMetric,
    /// Generic conformance check against a declared standard.
    ConformanceCheck,
    /// Application-defined query type.
    Custom(String),
}

// ── Query Scope ──────────────────────────────────────────────────────

/// Defines the boundary of what a regulator key is permitted to ask.
///
/// Scopes are issued by the data owner and cannot be widened after creation.
/// The scope itself is attested and included in the regulator key's
/// H33Primitive chain.
#[derive(Debug, Clone)]
pub struct QueryScope {
    /// The set of query types this key is authorized to execute.
    pub allowed_queries: Vec<QueryType>,
    /// The tenant whose data this key can query.
    pub tenant_id: String,
    /// Unix timestamp (nanoseconds) when this scope was issued.
    pub issued_at: u64,
    /// Optional expiration. `None` means the scope is valid until explicitly revoked.
    pub expires_at: Option<u64>,
    /// Whether the data owner can revoke this scope after issuance.
    pub revocable: bool,
}

// ── Key Type ─────────────────────────────────────────────────────────

/// The three principal key types in the Cachee access model.
///
/// These are not encryption keys — they are *capability tokens* that define
/// what operations a holder can perform against attested data.
#[derive(Debug, Clone)]
pub enum KeyType {
    /// Full access: can decrypt, query, attest, and manage.
    Owner,
    /// Scoped ZK query capability: can ask specific questions, cannot decrypt.
    Regulator {
        /// The scope constraining this key's capabilities.
        scope: QueryScope,
    },
    /// Read-only proof verification: can verify attestations, cannot query or decrypt.
    Auditor,
}

// ── Regulator Key ────────────────────────────────────────────────────

/// Practical constraints on regulator key usage
#[derive(Debug, Clone)]
pub struct KeyConstraints {
    /// Maximum queries per hour (prevent abuse)
    pub max_queries_per_hour: u64,
    /// Maximum queries per day
    pub max_queries_per_day: u64,
    /// Maximum proof size in bytes (controls circuit complexity)
    pub max_proof_size_bytes: usize,
    /// Cost limit per query in compute-seconds
    pub max_compute_secs_per_query: f64,
    /// Allowed data schemas (restrict queryable fields)
    pub allowed_schemas: Vec<String>,
}

/// A regulator-issued key with scoped ZK query capability.
///
/// The key itself is attested by H33 Substrate at creation time, so there
/// is a verifiable record that the data owner authorized this specific
/// set of queries for this specific regulator.
#[derive(Debug, Clone)]
pub struct RegulatorKey {
    /// Unique identifier for this key (SHA3-256 of key material).
    pub key_id: [u8; 32],
    /// The scope defining what this key can do.
    pub scope: QueryScope,
    /// The data owner's ML-DSA-65 public key that issued this regulator key.
    pub issuer_pk: Vec<u8>,
    /// Unix timestamp (nanoseconds) when this key was created.
    pub created_at: u64,
    /// H33Primitive attesting the key issuance event itself.
    /// Present when the key was created through the attested issuance flow.
    pub attestation: Option<H33Primitive>,
    /// Practical constraints on key usage (rate limits, proof size, etc.)
    pub constraints: KeyConstraints,
}

// ── Query Answer ─────────────────────────────────────────────────────

/// The answer to a zero-knowledge query.
///
/// All answers are proven via STARK — the verifier learns the answer
/// but nothing about the underlying data.
#[derive(Debug, Clone)]
pub enum QueryAnswer {
    /// Binary pass/fail (e.g., AML exposure: clean or flagged).
    Pass,
    /// Binary pass/fail — negative result.
    Fail,
    /// Numeric score (e.g., compliance score 0.0–1.0).
    Score(f64),
    /// Threshold comparison (e.g., collateral: value vs. required limit).
    Threshold {
        /// The computed value.
        value: f64,
        /// The threshold limit it was compared against.
        limit: f64,
    },
}

// ── ZK Query Result ──────────────────────────────────────────────────

/// The result of executing a zero-knowledge query.
///
/// Contains the answer, the STARK proof that the answer is correct,
/// and an H33Primitive attesting the query execution itself.
#[derive(Debug, Clone)]
pub struct ZkQueryResult {
    /// The type of query that was executed.
    pub query_type: QueryType,
    /// The proven answer.
    pub answer: QueryAnswer,
    /// STARK proof bytes proving the answer is correct without revealing data.
    pub proof: Vec<u8>,
    /// Unix timestamp (nanoseconds) when the query was executed.
    pub timestamp: u64,
    /// H33Primitive attesting the query execution event.
    pub attestation: H33Primitive,
}
