//! Cachee Archive Bundle (CAB) — self-contained, independently verifiable attestation package.
//!
//! A CAB contains everything needed to verify an H33-74 attestation without
//! Cachee, without H33, and without any network dependency. Courts, regulators,
//! and auditors can verify a CAB using only NIST public specifications and
//! the signer's public keys (included in the bundle).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Magic bytes identifying a Cachee Archive Bundle.
pub const CAB_MAGIC: [u8; 4] = *b"CAB1";

// ── Computation Fingerprint (Guarantee #1) ──────────────────────────

/// Deterministic computation identity — NOT just output hash.
///
/// Two identical outputs from different computations are NOT the same cache entry.
/// This promotes Cachee from "cached value" to "reproducible computation artifact".
/// The fingerprint captures the full identity of the computation: what went in,
/// what function was applied, what parameters were used, and what engine version
/// produced the result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationFingerprint {
    /// SHA3-256 of the input data.
    pub input_hash: [u8; 32],
    /// Hash of the computation definition (function/circuit/program bytecode).
    pub computation_hash: [u8; 32],
    /// Hash of the parameter set (FHE params, STARK config, etc.).
    pub parameter_hash: [u8; 32],
    /// Engine/library/circuit version that produced this result.
    pub version: ComputationVersion,
    /// Optional hardware class (if non-deterministic risk exists).
    pub hardware_class: Option<HardwareClass>,
}

impl ComputationFingerprint {
    /// Create an empty fingerprint (all-zero hashes, no identity).
    ///
    /// Used when a SET command is issued without a computation fingerprint
    /// and strict mode is disabled.
    pub fn empty() -> Self {
        Self {
            input_hash: [0u8; 32],
            computation_hash: [0u8; 32],
            parameter_hash: [0u8; 32],
            version: ComputationVersion {
                engine: String::new(),
                version: String::new(),
                circuit_id: None,
            },
            hardware_class: None,
        }
    }

    /// Compute a deterministic hash of this fingerprint for inclusion in content addresses.
    ///
    /// `SHA3-256(input_hash || computation_hash || parameter_hash || version_bytes || hardware_class_byte)`
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.input_hash);
        hasher.update(self.computation_hash);
        hasher.update(self.parameter_hash);
        hasher.update(self.version.engine.as_bytes());
        hasher.update(self.version.version.as_bytes());
        if let Some(ref circuit_id) = self.version.circuit_id {
            hasher.update(circuit_id.as_bytes());
        }
        match &self.hardware_class {
            None => hasher.update([0u8]),
            Some(HardwareClass::Deterministic) => hasher.update([1u8]),
            Some(HardwareClass::NearDeterministic) => hasher.update([2u8]),
            Some(HardwareClass::NonDeterministic(id)) => {
                hasher.update([3u8]);
                hasher.update(id.as_bytes());
            }
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Serialize to bytes for inclusion in the CAB wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.input_hash);
        buf.extend_from_slice(&self.computation_hash);
        buf.extend_from_slice(&self.parameter_hash);
        // Version: length-prefixed strings
        let engine_bytes = self.version.engine.as_bytes();
        buf.extend_from_slice(&(engine_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(engine_bytes);
        let version_bytes = self.version.version.as_bytes();
        buf.extend_from_slice(&(version_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(version_bytes);
        match &self.version.circuit_id {
            Some(cid) => {
                buf.push(1);
                let cid_bytes = cid.as_bytes();
                buf.extend_from_slice(&(cid_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(cid_bytes);
            }
            None => buf.push(0),
        }
        // Hardware class
        match &self.hardware_class {
            None => buf.push(0),
            Some(HardwareClass::Deterministic) => buf.push(1),
            Some(HardwareClass::NearDeterministic) => buf.push(2),
            Some(HardwareClass::NonDeterministic(id)) => {
                buf.push(3);
                let id_bytes = id.as_bytes();
                buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
                buf.extend_from_slice(id_bytes);
            }
        }
        buf
    }

    /// Deserialize from bytes. Returns the fingerprint and the number of bytes consumed.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<(Self, usize)> {
        let mut pos = 0usize;
        if bytes.len() < 96 {
            anyhow::bail!("ComputationFingerprint too short");
        }
        let input_hash: [u8; 32] = bytes[pos..pos + 32].try_into()?;
        pos += 32;
        let computation_hash: [u8; 32] = bytes[pos..pos + 32].try_into()?;
        pos += 32;
        let parameter_hash: [u8; 32] = bytes[pos..pos + 32].try_into()?;
        pos += 32;

        // Version
        if bytes.len() < pos + 2 {
            anyhow::bail!("ComputationFingerprint: missing engine length");
        }
        let engine_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into()?) as usize;
        pos += 2;
        if bytes.len() < pos + engine_len {
            anyhow::bail!("ComputationFingerprint: engine string truncated");
        }
        let engine = String::from_utf8(bytes[pos..pos + engine_len].to_vec())?;
        pos += engine_len;

        if bytes.len() < pos + 2 {
            anyhow::bail!("ComputationFingerprint: missing version length");
        }
        let ver_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into()?) as usize;
        pos += 2;
        if bytes.len() < pos + ver_len {
            anyhow::bail!("ComputationFingerprint: version string truncated");
        }
        let version_str = String::from_utf8(bytes[pos..pos + ver_len].to_vec())?;
        pos += ver_len;

        if pos >= bytes.len() {
            anyhow::bail!("ComputationFingerprint: missing circuit_id flag");
        }
        let has_circuit = bytes[pos];
        pos += 1;
        let circuit_id = if has_circuit == 1 {
            if bytes.len() < pos + 2 {
                anyhow::bail!("ComputationFingerprint: missing circuit_id length");
            }
            let cid_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into()?) as usize;
            pos += 2;
            if bytes.len() < pos + cid_len {
                anyhow::bail!("ComputationFingerprint: circuit_id string truncated");
            }
            let cid = String::from_utf8(bytes[pos..pos + cid_len].to_vec())?;
            pos += cid_len;
            Some(cid)
        } else {
            None
        };

        // Hardware class
        if pos >= bytes.len() {
            anyhow::bail!("ComputationFingerprint: missing hardware_class");
        }
        let hw_tag = bytes[pos];
        pos += 1;
        let hardware_class = match hw_tag {
            0 => None,
            1 => Some(HardwareClass::Deterministic),
            2 => Some(HardwareClass::NearDeterministic),
            3 => {
                if bytes.len() < pos + 2 {
                    anyhow::bail!("ComputationFingerprint: missing hw id length");
                }
                let id_len = u16::from_be_bytes(bytes[pos..pos + 2].try_into()?) as usize;
                pos += 2;
                if bytes.len() < pos + id_len {
                    anyhow::bail!("ComputationFingerprint: hw id truncated");
                }
                let id = String::from_utf8(bytes[pos..pos + id_len].to_vec())?;
                pos += id_len;
                Some(HardwareClass::NonDeterministic(id))
            }
            other => anyhow::bail!("ComputationFingerprint: invalid hw class tag {other}"),
        };

        Ok((
            Self {
                input_hash,
                computation_hash,
                parameter_hash,
                version: ComputationVersion {
                    engine,
                    version: version_str,
                    circuit_id,
                },
                hardware_class,
            },
            pos,
        ))
    }
}

/// Engine/library/circuit version that produced a computation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationVersion {
    /// Engine name (e.g., "cachee-core", "h33-stark").
    pub engine: String,
    /// Semantic version string.
    pub version: String,
    /// Optional circuit identifier (for ZK circuits).
    pub circuit_id: Option<String>,
}

/// Hardware class — whether the computation is deterministic on this hardware.
///
/// x86/ARM integer operations are fully deterministic. NEON/AVX floating-point
/// operations may introduce rounding variance. GPU and FPGA computations are
/// generally non-deterministic and must be explicitly identified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareClass {
    /// Fully deterministic (x86/ARM with no floating-point variance).
    Deterministic,
    /// Near-deterministic (NEON/AVX with controlled rounding).
    NearDeterministic,
    /// Non-deterministic (GPU, custom FPGA) — include hardware identifier.
    NonDeterministic(String),
}

/// Current CAB format version.
pub const CAB_VERSION: u16 = 1;

// ── Computation Type ─────────────────────────────────────────────────

/// The type of computation that was attested.
///
/// Each variant maps to a two-byte discriminant for compact binary encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputationType {
    /// Biometric authentication (FHE inner-product match).
    BiometricAuth,
    /// Document integrity attestation.
    DocumentAttest,
    /// Supply-chain provenance verification.
    SupplyChainVerify,
    /// Financial audit trail entry.
    FinancialAudit,
    /// AI model weight or inference attestation.
    AIModelAttest,
    /// Post-quantum migration checkpoint.
    PostQuantumMigration,
    /// Application-defined computation type.
    Custom(u16),
}

impl ComputationType {
    /// Encode to a two-byte discriminant.
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::BiometricAuth => 0x01,
            Self::DocumentAttest => 0x02,
            Self::SupplyChainVerify => 0x03,
            Self::FinancialAudit => 0x04,
            Self::AIModelAttest => 0x05,
            Self::PostQuantumMigration => 0x12,
            Self::Custom(v) => *v,
        }
    }

    /// Decode from a two-byte discriminant.
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x01 => Self::BiometricAuth,
            0x02 => Self::DocumentAttest,
            0x03 => Self::SupplyChainVerify,
            0x04 => Self::FinancialAudit,
            0x05 => Self::AIModelAttest,
            0x12 => Self::PostQuantumMigration,
            other => Self::Custom(other),
        }
    }
}

// ── Completeness Level ───────────────────────────────────────────────

/// How complete the attestation evidence in this bundle is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletenessLevel {
    /// Full evidence: genesis seal, ZK proof, and all three PQ signatures.
    Complete,
    /// Some subset of evidence is present (e.g., missing one signature family).
    Partial,
    /// At least two of three PQ signature families are present and valid.
    MinimalViable,
}

// ── Family Status ────────────────────────────────────────────────────

/// Lifecycle status of a PQ signature family within a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyStatus {
    /// Family is active and fully trusted.
    Active,
    /// Family is deprecated; must be replaced before the given deadline (Unix ns).
    DeprecatedWithNotice {
        /// Unix timestamp (nanoseconds) after which this family is no longer accepted.
        deadline: u64,
    },
    /// Family has been revoked and must not be trusted.
    Revoked {
        /// Human-readable reason for revocation.
        reason: String,
    },
}

// ── H33 Primitive (58 bytes) ─────────────────────────────────────────

/// The 58-byte H33 core primitive — the irreducible attestation unit.
///
/// This is the same primitive defined in the H33 Substrate specification.
/// It contains the value hash, PQ family prefixes, and feature flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H33Primitive {
    /// Primitive format version.
    pub version: u8,
    /// Attestation timestamp (8 bytes, big-endian nanoseconds since epoch).
    pub timestamp: [u8; 8],
    /// SHA3-256 hash of the attested value.
    pub value_hash: [u8; 32],
    /// ML-DSA-65 signature prefix (first 2 bytes of the full signature).
    pub mldsa_prefix: [u8; 2],
    /// FALCON-512 signature prefix (first 2 bytes of the full signature).
    pub falcon_prefix: [u8; 2],
    /// SLH-DSA-SHA2-128f signature prefix (first 2 bytes of the full signature).
    pub slhdsa_prefix: [u8; 2],
    /// Feature and capability flags.
    pub flags: [u8; 11],
}

impl H33Primitive {
    /// Total serialized size of the primitive in bytes.
    pub const SIZE: usize = 58;

    /// Serialize the primitive to a fixed-size byte array.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.version;
        buf[1..9].copy_from_slice(&self.timestamp);
        buf[9..41].copy_from_slice(&self.value_hash);
        buf[41..43].copy_from_slice(&self.mldsa_prefix);
        buf[43..45].copy_from_slice(&self.falcon_prefix);
        buf[45..47].copy_from_slice(&self.slhdsa_prefix);
        buf[47..58].copy_from_slice(&self.flags);
        buf
    }

    /// Deserialize from a byte slice. Returns `None` if the slice is too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            version: bytes[0],
            timestamp: bytes[1..9].try_into().ok()?,
            value_hash: bytes[9..41].try_into().ok()?,
            mldsa_prefix: bytes[41..43].try_into().ok()?,
            falcon_prefix: bytes[43..45].try_into().ok()?,
            slhdsa_prefix: bytes[45..47].try_into().ok()?,
            flags: bytes[47..58].try_into().ok()?,
        })
    }
}

// ── Signer Public Keys ──────────────────────────────────────────────

/// The three PQ public keys needed to verify bundle signatures.
///
/// Including these in the bundle makes verification fully self-contained:
/// no key server lookup is required.
#[derive(Debug, Clone)]
pub struct SignerPublicKeys {
    /// ML-DSA-65 (Dilithium) public key — 1,952 bytes.
    pub mldsa65: Vec<u8>,
    /// FALCON-512 public key — 897 bytes.
    pub falcon512: Vec<u8>,
    /// SLH-DSA-SHA2-128f (SPHINCS+) public key — 32 bytes.
    pub slhdsa128f: Vec<u8>,
}

// ── Signature Bundle ─────────────────────────────────────────────────

/// The three PQ signatures over the content hash.
///
/// Three independent mathematical hardness assumptions (MLWE lattices,
/// NTRU lattices, stateless hash functions) ensure the attestation survives
/// even if one family is broken.
#[derive(Debug, Clone)]
pub struct SignatureBundle {
    /// ML-DSA-65 (Dilithium) signature — 3,309 bytes.
    pub mldsa65: Vec<u8>,
    /// FALCON-512 signature — 690 bytes.
    pub falcon512: Vec<u8>,
    /// SLH-DSA-SHA2-128f (SPHINCS+) signature — 17,088 bytes.
    pub slhdsa128f: Vec<u8>,
}

/// Identity of the signer who produced a bundle.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignerIdentity {
    pub key_id: [u8; 32],
    pub key_version: u32,
    pub families: Vec<String>,
    pub issuer: String,
    pub posture: String,
}

impl Default for SignerIdentity {
    fn default() -> Self {
        Self {
            key_id: [0; 32],
            key_version: 0,
            families: vec![],
            issuer: String::new(),
            posture: "unknown".to_string(),
        }
    }
}

// ── On-Chain Anchor ──────────────────────────────────────────────────

/// 74-byte on-chain commitment linking the bundle to a blockchain anchor.
///
/// The first 32 bytes are the Merkle root hash committed on-chain.
/// The remaining 42 bytes are the retrieval pointer: a 10-byte node ID
/// followed by a 32-byte receipt lookup key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainAnchor {
    /// Merkle root hash committed on-chain (32 bytes).
    pub hash: [u8; 32],
    /// Retrieval pointer: 10-byte node ID + 32-byte receipt lookup key.
    pub retrieval_pointer: [u8; 42],
}

impl OnChainAnchor {
    /// Total serialized size of the on-chain anchor.
    pub const SIZE: usize = 74;

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..32].copy_from_slice(&self.hash);
        buf[32..74].copy_from_slice(&self.retrieval_pointer);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            hash: bytes[0..32].try_into().ok()?,
            retrieval_pointer: bytes[32..74].try_into().ok()?,
        })
    }
}

// ── Verification Result ──────────────────────────────────────────────

/// Per-family and aggregate verification outcome.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationResult {
    pub verdict: VerificationVerdict,
    pub cryptographic: CryptographicValidity,
    pub structural: StructuralValidity,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum VerificationVerdict {
    Valid,
    ValidWithWarnings(Vec<String>),
    Invalid(String),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptographicValidity {
    pub mldsa_valid: bool,
    pub falcon_valid: bool,
    pub slhdsa_valid: bool,
    pub two_of_three: bool,
    pub all_three: bool,
    pub deprecated_family_present: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StructuralValidity {
    pub magic_valid: bool,
    pub version_supported: bool,
    pub fingerprint_present: bool,
    pub content_hash_matches: bool,
    pub timestamp_valid: bool,
    pub signer_identity_present: bool,
}

impl VerificationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self.verdict, VerificationVerdict::Valid | VerificationVerdict::ValidWithWarnings(_))
    }
    // Backward compat accessors
    pub fn valid(&self) -> bool { self.is_valid() }
    pub fn mldsa_valid(&self) -> bool { self.cryptographic.mldsa_valid }
    pub fn falcon_valid(&self) -> bool { self.cryptographic.falcon_valid }
    pub fn slhdsa_valid(&self) -> bool { self.cryptographic.slhdsa_valid }
    pub fn two_of_three(&self) -> bool { self.cryptographic.two_of_three }
}

// ── Cachee Archive Bundle ────────────────────────────────────────────

/// A self-contained, independently verifiable attestation package.
///
/// Contains the H33 primitive, all three PQ signatures, the signer's public
/// keys, and an optional on-chain anchor. Everything needed to verify the
/// attestation is included — no network calls, no key lookups, no trust
/// in any third party beyond NIST public specifications.
#[derive(Debug, Clone)]
pub struct CacheeArchiveBundle {
    /// Format identifier — always `CAB1`.
    pub magic: [u8; 4],
    /// Bundle format version.
    pub version: u16,
    /// The 58-byte H33 core primitive.
    pub primitive: H33Primitive,
    /// SHA3-256 hash of the original content that was attested.
    pub content_hash: [u8; 32],
    /// The type of computation that produced this attestation.
    pub computation_type: ComputationType,
    /// Attestation creation time in nanoseconds since Unix epoch.
    pub timestamp_ns: u64,
    /// The three PQ public keys used to sign this bundle.
    pub signer_keys: SignerPublicKeys,
    /// The three PQ signatures over the content hash.
    pub signatures: SignatureBundle,
    /// CBOR-encoded application metadata.
    pub metadata: Vec<u8>,
    /// Optional 74-byte on-chain anchor (present when the bundle has been anchored).
    pub on_chain_anchor: Option<OnChainAnchor>,
    /// How complete the evidence in this bundle is.
    pub completeness: CompletenessLevel,
    /// Deterministic computation identity — NOT just output hash.
    /// Two identical outputs from different computations are NOT the same cache entry.
    pub computation_fingerprint: ComputationFingerprint,
    /// Identity of the signer who produced this bundle.
    pub signer_identity: SignerIdentity,
}

impl CacheeArchiveBundle {
    /// Compute the deterministic content address for this bundle.
    ///
    /// `SHA3-256(primitive_bytes || content_hash || computation_fingerprint_digest)`
    /// — this is the retrieval key used for DHT routing and archive lookups.
    ///
    /// The computation fingerprint is included so that two identical outputs
    /// from different computations produce different content addresses.
    pub fn content_address(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(self.primitive.to_bytes());
        hasher.update(self.content_hash);
        hasher.update(self.computation_fingerprint.digest());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Serialize the bundle to its canonical binary representation.
    ///
    /// Wire format (all multi-byte integers are big-endian):
    /// ```text
    /// [4]  magic
    /// [2]  version
    /// [58] primitive
    /// [32] content_hash
    /// [2]  computation_type
    /// [8]  timestamp_ns
    /// [2]  mldsa65_pk_len  + [N] mldsa65_pk
    /// [2]  falcon512_pk_len + [N] falcon512_pk
    /// [2]  slhdsa128f_pk_len + [N] slhdsa128f_pk
    /// [2]  mldsa65_sig_len + [N] mldsa65_sig
    /// [2]  falcon512_sig_len + [N] falcon512_sig
    /// [2]  slhdsa128f_sig_len + [N] slhdsa128f_sig
    /// [4]  metadata_len + [N] metadata
    /// [1]  has_anchor (0 or 1)
    /// [74] anchor (if has_anchor == 1)
    /// [1]  completeness (0=Complete, 1=Partial, 2=MinimalViable)
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.compressed_size());

        // Header
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.version.to_be_bytes());

        // Primitive (58 bytes)
        buf.extend_from_slice(&self.primitive.to_bytes());

        // Content hash
        buf.extend_from_slice(&self.content_hash);

        // Computation type
        buf.extend_from_slice(&self.computation_type.to_u16().to_be_bytes());

        // Timestamp
        buf.extend_from_slice(&self.timestamp_ns.to_be_bytes());

        // Signer public keys (length-prefixed)
        write_length_prefixed_u16(&mut buf, &self.signer_keys.mldsa65);
        write_length_prefixed_u16(&mut buf, &self.signer_keys.falcon512);
        write_length_prefixed_u16(&mut buf, &self.signer_keys.slhdsa128f);

        // Signatures (length-prefixed)
        write_length_prefixed_u16(&mut buf, &self.signatures.mldsa65);
        write_length_prefixed_u16(&mut buf, &self.signatures.falcon512);
        write_length_prefixed_u16(&mut buf, &self.signatures.slhdsa128f);

        // Metadata (length-prefixed, 4-byte length for larger payloads)
        buf.extend_from_slice(&(self.metadata.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.metadata);

        // On-chain anchor
        match &self.on_chain_anchor {
            Some(anchor) => {
                buf.push(1);
                buf.extend_from_slice(&anchor.to_bytes());
            }
            None => {
                buf.push(0);
            }
        }

        // Completeness
        buf.push(match self.completeness {
            CompletenessLevel::Complete => 0,
            CompletenessLevel::Partial => 1,
            CompletenessLevel::MinimalViable => 2,
        });

        // Computation fingerprint (length-prefixed, 4-byte length)
        let fp_bytes = self.computation_fingerprint.to_bytes();
        buf.extend_from_slice(&(fp_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&fp_bytes);

        // Signer identity (length-prefixed JSON blob)
        let identity_json = serde_json::to_vec(&self.signer_identity).unwrap_or_default();
        buf.extend_from_slice(&(identity_json.len() as u32).to_be_bytes());
        buf.extend_from_slice(&identity_json);

        buf
    }

    /// Deserialize a bundle from its canonical binary representation.
    ///
    /// Returns an error if the bytes are malformed, too short, or the magic
    /// bytes do not match `CAB1`.
    pub fn deserialize(bytes: &[u8]) -> anyhow::Result<Self> {
        let mut pos = 0usize;

        // Magic
        if bytes.len() < 4 {
            anyhow::bail!("CAB too short: missing magic bytes");
        }
        let magic: [u8; 4] = bytes[pos..pos + 4].try_into()?;
        if magic != CAB_MAGIC {
            anyhow::bail!("invalid CAB magic: expected CAB1, got {:?}", magic);
        }
        pos += 4;

        // Version
        let version = read_u16(bytes, &mut pos)?;

        // Primitive
        if bytes.len() < pos + H33Primitive::SIZE {
            anyhow::bail!("CAB too short: missing primitive");
        }
        let primitive = H33Primitive::from_bytes(&bytes[pos..])
            .ok_or_else(|| anyhow::anyhow!("failed to parse H33Primitive"))?;
        pos += H33Primitive::SIZE;

        // Content hash
        if bytes.len() < pos + 32 {
            anyhow::bail!("CAB too short: missing content_hash");
        }
        let content_hash: [u8; 32] = bytes[pos..pos + 32].try_into()?;
        pos += 32;

        // Computation type
        let comp_type_raw = read_u16(bytes, &mut pos)?;
        let computation_type = ComputationType::from_u16(comp_type_raw);

        // Timestamp
        let timestamp_ns = read_u64(bytes, &mut pos)?;

        // Signer public keys
        let mldsa65_pk = read_length_prefixed_u16(bytes, &mut pos)?;
        let falcon512_pk = read_length_prefixed_u16(bytes, &mut pos)?;
        let slhdsa128f_pk = read_length_prefixed_u16(bytes, &mut pos)?;

        // Signatures
        let mldsa65_sig = read_length_prefixed_u16(bytes, &mut pos)?;
        let falcon512_sig = read_length_prefixed_u16(bytes, &mut pos)?;
        let slhdsa128f_sig = read_length_prefixed_u16(bytes, &mut pos)?;

        // Metadata
        let metadata = read_length_prefixed_u32(bytes, &mut pos)?;

        // On-chain anchor
        if pos >= bytes.len() {
            anyhow::bail!("CAB too short: missing anchor flag");
        }
        let has_anchor = bytes[pos];
        pos += 1;
        let on_chain_anchor = if has_anchor == 1 {
            if bytes.len() < pos + OnChainAnchor::SIZE {
                anyhow::bail!("CAB too short: missing anchor data");
            }
            let anchor = OnChainAnchor::from_bytes(&bytes[pos..])
                .ok_or_else(|| anyhow::anyhow!("failed to parse OnChainAnchor"))?;
            pos += OnChainAnchor::SIZE;
            Some(anchor)
        } else {
            None
        };

        // Completeness
        if pos >= bytes.len() {
            anyhow::bail!("CAB too short: missing completeness");
        }
        let completeness = match bytes[pos] {
            0 => CompletenessLevel::Complete,
            1 => CompletenessLevel::Partial,
            2 => CompletenessLevel::MinimalViable,
            other => anyhow::bail!("invalid completeness level: {other}"),
        };
        pos += 1;

        // Computation fingerprint (length-prefixed, 4-byte length)
        let fp_data = read_length_prefixed_u32(bytes, &mut pos)?;
        let (computation_fingerprint, _) = ComputationFingerprint::from_bytes(&fp_data)?;

        // Signer identity (length-prefixed JSON blob, backward-compatible)
        let signer_identity = if pos + 4 <= bytes.len() {
            let identity_data = read_length_prefixed_u32(bytes, &mut pos).unwrap_or_default();
            if identity_data.is_empty() {
                SignerIdentity::default()
            } else {
                serde_json::from_slice::<SignerIdentity>(&identity_data)
                    .unwrap_or_default()
            }
        } else {
            SignerIdentity::default()
        };

        Ok(Self {
            magic,
            version,
            primitive,
            content_hash,
            computation_type,
            timestamp_ns,
            signer_keys: SignerPublicKeys {
                mldsa65: mldsa65_pk,
                falcon512: falcon512_pk,
                slhdsa128f: slhdsa128f_pk,
            },
            signatures: SignatureBundle {
                mldsa65: mldsa65_sig,
                falcon512: falcon512_sig,
                slhdsa128f: slhdsa128f_sig,
            },
            metadata,
            on_chain_anchor,
            completeness,
            computation_fingerprint,
            signer_identity,
        })
    }

    /// Verify this bundle's cryptographic signatures.
    ///
    /// # Signing scope
    ///
    /// The message signed by all three PQ families is `content_hash`,
    /// which is `SHA3-256(cached_value)`. This directly covers:
    ///
    /// - **The computation result** (the cached value itself, via its hash)
    ///
    /// The `content_address` (used for storage/retrieval) is computed as
    /// `SHA3-256(primitive || content_hash || fingerprint.digest())`, which
    /// indirectly binds:
    ///
    /// - **Computation identity** (input_hash, computation_hash, parameter_hash)
    /// - **Engine version** and **hardware class**
    ///
    /// The following are structural metadata, NOT directly signed:
    /// - Lifecycle state (mutable after signing)
    /// - Metadata blob (informational)
    /// - Provenance (set by daemon, not signer)
    /// - Signer identity (self-declared, verified via public key match)
    ///
    /// Returns a [`VerificationResult`] with per-family status using real PQ
    /// cryptographic verification (ML-DSA-65, FALCON-512, SLH-DSA-SHA2-128f).
    pub fn verify(&self) -> VerificationResult {
        use crate::crypto;

        let magic_valid = self.magic == CAB_MAGIC;

        // Verify magic
        if !magic_valid {
            return VerificationResult {
                verdict: VerificationVerdict::Invalid("invalid CAB magic".to_string()),
                cryptographic: CryptographicValidity {
                    mldsa_valid: false,
                    falcon_valid: false,
                    slhdsa_valid: false,
                    two_of_three: false,
                    all_three: false,
                    deprecated_family_present: false,
                },
                structural: StructuralValidity {
                    magic_valid: false,
                    version_supported: false,
                    fingerprint_present: false,
                    content_hash_matches: false,
                    timestamp_valid: false,
                    signer_identity_present: false,
                },
            };
        }

        // The message that was signed is the content hash
        let message = &self.content_hash;

        let mldsa_valid = crypto::verify_mldsa65(
            &self.signer_keys.mldsa65,
            message,
            &self.signatures.mldsa65,
        )
        .unwrap_or(false);

        let falcon_valid = crypto::verify_falcon512(
            &self.signer_keys.falcon512,
            message,
            &self.signatures.falcon512,
        )
        .unwrap_or(false);

        let slhdsa_valid = crypto::verify_slhdsa128f(
            &self.signer_keys.slhdsa128f,
            message,
            &self.signatures.slhdsa128f,
        )
        .unwrap_or(false);

        let valid_count = [mldsa_valid, falcon_valid, slhdsa_valid]
            .iter()
            .filter(|&&v| v)
            .count();
        let two_of_three = valid_count >= 2;
        let all_three = valid_count == 3;

        // Timestamp sanity: not zero
        let timestamp_valid = self.timestamp_ns > 0;

        // Content hash consistency: the primitive's value_hash should match content_hash
        let content_hash_matches = self.primitive.value_hash == self.content_hash;

        let version_supported = self.version == CAB_VERSION;
        let fingerprint_present = self.has_valid_fingerprint();
        let signer_identity_present = self.signer_identity.key_id != [0u8; 32];

        let cryptographic = CryptographicValidity {
            mldsa_valid,
            falcon_valid,
            slhdsa_valid,
            two_of_three,
            all_three,
            deprecated_family_present: false,
        };

        let structural = StructuralValidity {
            magic_valid,
            version_supported,
            fingerprint_present,
            content_hash_matches,
            timestamp_valid,
            signer_identity_present,
        };

        // Build warnings
        let mut warnings = Vec::new();
        if self.signer_identity.posture == "development" || self.signer_identity.posture == "Development" {
            warnings.push("development posture".to_string());
        }
        if !signer_identity_present {
            warnings.push("missing signer identity".to_string());
        }
        if !fingerprint_present {
            warnings.push("fingerprint not present".to_string());
        }

        let core_valid = content_hash_matches && two_of_three && timestamp_valid;

        let verdict = if !core_valid {
            let mut reasons = Vec::new();
            if !content_hash_matches { reasons.push("content hash mismatch"); }
            if !two_of_three { reasons.push("fewer than 2-of-3 signatures valid"); }
            if !timestamp_valid { reasons.push("invalid timestamp"); }
            VerificationVerdict::Invalid(reasons.join("; "))
        } else if !warnings.is_empty() {
            VerificationVerdict::ValidWithWarnings(warnings)
        } else {
            VerificationVerdict::Valid
        };

        VerificationResult {
            verdict,
            cryptographic,
            structural,
        }
    }

    /// Check if this bundle has a valid computation fingerprint (non-empty hashes).
    pub fn has_valid_fingerprint(&self) -> bool {
        self.computation_fingerprint.input_hash != [0u8; 32]
            && self.computation_fingerprint.computation_hash != [0u8; 32]
    }

    /// Estimate the total serialized size of this bundle in bytes.
    ///
    /// This is the uncompressed wire size. Typical CABs compress well because
    /// public keys and signatures have high entropy but metadata is often
    /// repetitive CBOR.
    pub fn compressed_size(&self) -> usize {
        4   // magic
        + 2 // version
        + H33Primitive::SIZE
        + 32 // content_hash
        + 2  // computation_type
        + 8  // timestamp_ns
        + 2 + self.signer_keys.mldsa65.len()
        + 2 + self.signer_keys.falcon512.len()
        + 2 + self.signer_keys.slhdsa128f.len()
        + 2 + self.signatures.mldsa65.len()
        + 2 + self.signatures.falcon512.len()
        + 2 + self.signatures.slhdsa128f.len()
        + 4 + self.metadata.len()
        + 1 // has_anchor flag
        + if self.on_chain_anchor.is_some() { OnChainAnchor::SIZE } else { 0 }
        + 1 // completeness
        + 4 + self.computation_fingerprint.to_bytes().len() // computation fingerprint
        + 4 + serde_json::to_vec(&self.signer_identity).unwrap_or_default().len() // signer identity
    }
}

// ── Wire helpers ─────────────────────────────────────────────────────

fn write_length_prefixed_u16(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> anyhow::Result<u16> {
    if bytes.len() < *pos + 2 {
        anyhow::bail!("unexpected end of CAB at offset {pos}");
    }
    let val = u16::from_be_bytes(bytes[*pos..*pos + 2].try_into()?);
    *pos += 2;
    Ok(val)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> anyhow::Result<u64> {
    if bytes.len() < *pos + 8 {
        anyhow::bail!("unexpected end of CAB at offset {pos}");
    }
    let val = u64::from_be_bytes(bytes[*pos..*pos + 8].try_into()?);
    *pos += 8;
    Ok(val)
}

fn read_length_prefixed_u16(bytes: &[u8], pos: &mut usize) -> anyhow::Result<Vec<u8>> {
    let len = read_u16(bytes, pos)? as usize;
    if bytes.len() < *pos + len {
        anyhow::bail!("unexpected end of CAB at offset {pos}, need {len} bytes");
    }
    let data = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(data)
}

fn read_length_prefixed_u32(bytes: &[u8], pos: &mut usize) -> anyhow::Result<Vec<u8>> {
    if bytes.len() < *pos + 4 {
        anyhow::bail!("unexpected end of CAB at offset {pos}");
    }
    let len = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into()?) as usize;
    *pos += 4;
    if bytes.len() < *pos + len {
        anyhow::bail!("unexpected end of CAB at offset {pos}, need {len} bytes");
    }
    let data = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Ok(data)
}
