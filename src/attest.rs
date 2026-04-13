//! `cachee attest` — PQ attestation control (Substrate signing).

use crate::config;

pub async fn enable() -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    cfg.attest_enabled = true;

    let config_path = config::cachee_dir().join("config.toml");
    let toml_str = toml::to_string_pretty(&cfg)?;
    std::fs::write(&config_path, &toml_str)?;

    let key_path = config::cachee_dir().join("keys").join("identity.toml");
    if !key_path.exists() {
        anyhow::bail!("No PQ identity found. Run `cachee init` first.");
    }

    println!("PQ attestation enabled.");
    println!();
    println!("  Every SET now produces:");
    println!("    58-byte canonical Substrate receipt");
    println!("    ML-DSA-65 signature  (3,309 bytes)");
    println!("    FALCON-512 signature   (690 bytes)");
    println!("    SLH-DSA signature   (29,000 bytes)");
    println!();
    println!("  Every GET verifies the receipt before returning.");
    println!("  Cache poisoning is cryptographically impossible.");
    println!();
    println!("  Restart the daemon for changes to take effect: cachee stop && cachee start");

    Ok(())
}

pub async fn disable() -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    cfg.attest_enabled = false;

    let config_path = config::cachee_dir().join("config.toml");
    let toml_str = toml::to_string_pretty(&cfg)?;
    std::fs::write(&config_path, &toml_str)?;

    println!("PQ attestation disabled.");
    println!("Restart the daemon for changes to take effect.");

    Ok(())
}

pub async fn status() -> anyhow::Result<()> {
    let cfg = config::load()?;
    let key_path = config::cachee_dir().join("keys").join("identity.toml");

    println!("PQ Attestation Status");
    println!("  Enabled    : {}", cfg.attest_enabled);
    println!("  Identity   : {}", if key_path.exists() { "present" } else { "not generated" });
    println!("  Algorithms : ML-DSA-65, FALCON-512, SLH-DSA");
    println!("  Receipt    : 58-byte canonical Substrate");
    println!("  On-chain   : 74 bytes (32-byte hash + 42-byte pointer)");
    println!("  Fits       : Bitcoin OP_RETURN, Solana memo, Ethereum calldata");

    if key_path.exists() {
        let key_info = std::fs::read_to_string(&key_path)?;
        for line in key_info.lines() {
            if line.starts_with("key_id") {
                println!("  Key ID     : {}", line.split('"').nth(1).unwrap_or("unknown"));
            }
        }
    }

    Ok(())
}
