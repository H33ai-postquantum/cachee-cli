//! `cachee init` — create config directory, generate PQ keypair, write config.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level Cachee configuration.
///
/// Loaded from `~/.cachee/config.toml` by `cachee init` and read on every
/// `cachee start`. All verification and trust policy lives in the
/// `verification` section.
#[derive(Debug, Serialize, Deserialize)]
pub struct CacheeConfig {
    /// Port for the RESP server.
    pub port: u16,
    /// Maximum number of cache entries.
    pub max_keys: usize,
    /// Default TTL in seconds.
    pub default_ttl: u32,
    /// Whether the L0 hot tier is enabled.
    pub l0_enabled: bool,
    /// Number of L0 shards.
    pub l0_shards: usize,
    /// Maximum entries in the L0 hot tier.
    pub l0_max_keys: usize,
    /// Whether PQ attestation is enabled.
    pub attest_enabled: bool,
    /// Port for the Prometheus metrics endpoint.
    pub metrics_port: u16,
    /// Path to the data directory.
    pub data_dir: String,
    /// Billing plan configuration.
    pub plan: Plan,
    /// Verification cost model configuration (LOCK 4).
    #[serde(default)]
    pub verification: VerificationConfig,
    /// Issuer identity for this daemon instance.
    /// Flows into CacheSlot provenance and SignerIdentity.
    #[serde(default = "default_issuer_id")]
    pub issuer_id: String,
}

/// Default issuer ID — from env or process ID.
fn default_issuer_id() -> String {
    std::env::var("CACHEE_ISSUER_ID").unwrap_or_else(|_| {
        format!("cachee-{}", std::process::id())
    })
}

/// Billing plan configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct Plan {
    /// Plan tier name (e.g. "free", "starter", "professional", "enterprise").
    pub tier: String,
    /// Monthly operation allowance.
    pub ops_per_month: u64,
    /// Per-operation rate in USD.
    pub rate_per_op: f64,
    /// Memory cap in terabytes.
    #[serde(default)]
    pub memory_cap_tb: f64,
    /// Overage cost per terabyte.
    #[serde(default)]
    pub overage_per_tb: f64,
}

/// Verification cost model configuration (LOCK 4).
///
/// Controls how aggressively Cachee verifies cached results on read.
/// This is the fundamental tradeoff between security posture and performance.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Verification mode: "always_verify", "trust_cached", "probabilistic", "age_weighted".
    #[serde(default = "default_verification_mode")]
    pub mode: String,
    /// Fraction of reads that trigger full verification (for probabilistic mode).
    #[serde(default)]
    pub sample_rate: f64,
    /// Maximum age in seconds before mandatory re-verification (for age_weighted mode).
    #[serde(default = "default_max_age")]
    pub max_age_secs: u64,
    /// Reject SET operations that do not include a computation fingerprint.
    #[serde(default)]
    pub strict_fingerprint: bool,
    /// Per-computation-type verification mode overrides.
    #[serde(default)]
    pub overrides: std::collections::HashMap<String, String>,
    /// Conflict policy for writes: "reject", "fork", or "supersede".
    #[serde(default = "default_conflict_policy")]
    pub conflict_policy: String,
    /// Whether plain GET returns data or requires GETVERIFIED.
    /// "safe" = GET returns error directing user to GETVERIFIED
    /// "compatible" = GET works as normal Redis (no guarantees)
    #[serde(default = "default_read_mode")]
    pub read_mode: String,
    /// Whether the verification mode can be downgraded at runtime.
    /// When locked, mode can only be upgraded (e.g., trust_cached -> always_verify),
    /// never downgraded (e.g., always_verify -> trust_cached).
    #[serde(default)]
    pub mode_locked: bool,
    /// Minimum verification mode allowed. Cannot go below this.
    #[serde(default)]
    pub minimum_mode: Option<String>,
    /// Write policy: "allow_unsigned", "warn_unsigned", "require_signed".
    #[serde(default = "default_write_policy")]
    pub write_policy: String,
    /// Allow exporting unsigned bundles.
    #[serde(default)]
    pub allow_unsigned_export: bool,
    /// Allow unsigned bundles from federation peers.
    #[serde(default)]
    pub allow_unsigned_federation: bool,
}

fn default_write_policy() -> String { "allow_unsigned".to_string() }

/// Default verification mode: trust cached results without re-verifying.
fn default_verification_mode() -> String {
    "trust_cached".to_string()
}

/// Default maximum age before re-verification: 3600 seconds (1 hour).
fn default_max_age() -> u64 {
    3600
}

/// Default conflict policy: reject conflicting writes.
fn default_conflict_policy() -> String {
    "reject".to_string()
}

/// Default read mode: compatible (GET works as normal Redis).
fn default_read_mode() -> String {
    "compatible".to_string()
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            mode: default_verification_mode(),
            sample_rate: 0.01,
            max_age_secs: default_max_age(),
            strict_fingerprint: false,
            overrides: std::collections::HashMap::new(),
            conflict_policy: default_conflict_policy(),
            read_mode: default_read_mode(),
            mode_locked: false,
            minimum_mode: None,
            write_policy: default_write_policy(),
            allow_unsigned_export: false,
            allow_unsigned_federation: false,
        }
    }
}

impl Default for CacheeConfig {
    fn default() -> Self {
        Self {
            port: 6380,
            max_keys: 1_000_000,
            default_ttl: 3600,
            l0_enabled: true,
            l0_shards: 64,
            l0_max_keys: 100_000,
            attest_enabled: false,
            metrics_port: 9090,
            data_dir: cachee_dir().to_string_lossy().to_string(),
            plan: Plan {
                tier: "free".to_string(),
                ops_per_month: 10_000_000,
                rate_per_op: 0.0,
                memory_cap_tb: 0.0,
                overage_per_tb: 0.0,
            },
            verification: VerificationConfig::default(),
            issuer_id: default_issuer_id(),
        }
    }
}

pub fn cachee_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cachee")
}

pub async fn init(port: u16, max_keys: usize, ttl: u32) -> anyhow::Result<()> {
    let dir = cachee_dir();

    // Create directories
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(dir.join("keys"))?;
    std::fs::create_dir_all(dir.join("data"))?;

    // Generate config
    let config = CacheeConfig {
        port,
        max_keys,
        default_ttl: ttl,
        data_dir: dir.to_string_lossy().to_string(),
        ..Default::default()
    };

    let config_path = dir.join("config.toml");
    let toml_str = toml::to_string_pretty(&config)?;
    std::fs::write(&config_path, &toml_str)?;

    // Generate PQ keypair placeholder identity
    let key_id = hex::encode(&rand::random::<[u8; 16]>());
    let key_info = format!(
        "# Cachee PQ Identity\n# Generated: {}\nkey_id = \"{}\"\nalgorithms = [\"ML-DSA-65\", \"FALCON-512\", \"SLH-DSA\"]\n",
        chrono_placeholder(),
        key_id,
    );
    std::fs::write(dir.join("keys").join("identity.toml"), &key_info)?;

    // Generate real PQ keypairs
    use crate::pq_keys::{PqKeySet, CryptoPosture};
    let pq_keys = PqKeySet::generate(CryptoPosture::Production);
    let keys_path = dir.join("keys");
    pq_keys.save(&keys_path).map_err(|e| anyhow::anyhow!("PQ keygen failed: {}", e))?;

    println!("Cachee initialized at {}", dir.display());
    println!();
    println!("  Config    : {}", config_path.display());
    println!("  Port      : {port}");
    println!("  Max keys  : {max_keys}");
    println!("  TTL       : {ttl}s");
    println!("  L0 tier   : enabled (64 shards)");
    println!("  PQ Keys   : ML-DSA-65 + FALCON-512 + SLH-DSA-128f");
    println!("  Keys at   : {}", keys_path.display());
    println!("  Attest    : disabled (enable with `cachee attest enable`)");
    println!("  Verify    : trust_cached (1% probabilistic sample)");
    println!("  Strict FP : disabled");
    println!("  Key ID    : {key_id}");
    println!("  Plan      : Free (10M ops/month)");
    println!();
    println!("  Start with: cachee start");
    println!("  Upgrade:    cachee plan upgrade");

    Ok(())
}

fn chrono_placeholder() -> String {
    // Avoid chrono dep — use system time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{now}")
}

pub fn load() -> anyhow::Result<CacheeConfig> {
    let config_path = cachee_dir().join("config.toml");
    if !config_path.exists() {
        anyhow::bail!("Cachee not initialized. Run `cachee init` first.");
    }
    let contents = std::fs::read_to_string(&config_path)?;
    let config: CacheeConfig = toml::from_str(&contents)?;
    Ok(config)
}
