//! `cachee init` — create config directory, generate PQ keypair, write config.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct CacheeConfig {
    pub port: u16,
    pub max_keys: usize,
    pub default_ttl: u32,
    pub l0_enabled: bool,
    pub l0_shards: usize,
    pub l0_max_keys: usize,
    pub attest_enabled: bool,
    pub metrics_port: u16,
    pub data_dir: String,
    pub plan: Plan,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Plan {
    pub tier: String,
    pub ops_per_month: u64,
    pub rate_per_op: f64,
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
            },
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

    // Generate PQ keypair placeholder
    // In production: Dilithium + FALCON + SPHINCS+ keypair generation
    let key_id = hex::encode(&rand::random::<[u8; 16]>());
    let key_info = format!(
        "# Cachee PQ Identity\n# Generated: {}\nkey_id = \"{}\"\nalgorithms = [\"ML-DSA-65\", \"FALCON-512\", \"SLH-DSA\"]\n",
        chrono_placeholder(),
        key_id,
    );
    std::fs::write(dir.join("keys").join("identity.toml"), &key_info)?;

    println!("Cachee initialized at {}", dir.display());
    println!();
    println!("  Config    : {}", config_path.display());
    println!("  Port      : {port}");
    println!("  Max keys  : {max_keys}");
    println!("  TTL       : {ttl}s");
    println!("  L0 tier   : enabled (64 shards)");
    println!("  Attest    : disabled (enable with `cachee attest enable`)");
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
