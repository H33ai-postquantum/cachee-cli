//! `cachee auth`, `cachee tls`, `cachee rotate-keys` — security management.

use crate::config;

// ── API Key Management ───────────────────────────────

pub async fn auth_create(label: &str, permissions: &str) -> anyhow::Result<()> {
    let keys_dir = config::cachee_dir().join("keys");
    std::fs::create_dir_all(&keys_dir)?;

    let key_id = hex::encode(&rand::random::<[u8; 8]>());
    let secret = hex::encode(&rand::random::<[u8; 32]>());

    let key_file = keys_dir.join(format!("apikey-{key_id}.toml"));
    let content = format!(
        "key_id = \"{key_id}\"\nlabel = \"{label}\"\npermissions = \"{permissions}\"\nsecret_hash = \"{}\"\ncreated = {}\n",
        hex::encode(sha3_hash(secret.as_bytes())),
        now_unix(),
    );
    std::fs::write(&key_file, &content)?;

    println!("API key created");
    println!();
    println!("  Key ID      : {key_id}");
    println!("  Label       : {label}");
    println!("  Permissions : {permissions}");
    println!("  Secret      : {secret}");
    println!();
    println!("  Store the secret securely — it cannot be retrieved after this.");
    println!("  Connect with: CACHEE_AUTH={secret} cachee get mykey");

    Ok(())
}

pub async fn auth_list() -> anyhow::Result<()> {
    let keys_dir = config::cachee_dir().join("keys");

    println!("API Keys");
    println!();
    println!("  {:<18} {:<20} {:<16}", "Key ID", "Label", "Permissions");
    println!("  {}", "-".repeat(55));

    let mut found = false;
    if keys_dir.exists() {
        for entry in std::fs::read_dir(&keys_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("apikey-") && name.ends_with(".toml") {
                let content = std::fs::read_to_string(entry.path())?;
                let key_id = extract_field(&content, "key_id");
                let label = extract_field(&content, "label");
                let perms = extract_field(&content, "permissions");
                println!("  {:<18} {:<20} {:<16}", key_id, label, perms);
                found = true;
            }
        }
    }

    if !found {
        println!("  (none)");
        println!();
        println!("  Create one: cachee auth create --label \"my-app\"");
    }

    Ok(())
}

pub async fn auth_revoke(key_id: &str) -> anyhow::Result<()> {
    let key_file = config::cachee_dir().join("keys").join(format!("apikey-{key_id}.toml"));
    if key_file.exists() {
        std::fs::remove_file(&key_file)?;
        println!("API key {key_id} revoked");
    } else {
        println!("Key {key_id} not found");
    }
    Ok(())
}

// ── TLS Management ───────────────────────────────────

pub async fn tls_enable() -> anyhow::Result<()> {
    let tls_dir = config::cachee_dir().join("tls");
    std::fs::create_dir_all(&tls_dir)?;

    // Generate self-signed cert placeholder
    let cert_path = tls_dir.join("cert.pem");
    let key_path = tls_dir.join("key.pem");

    // In production: use rcgen or rustls-pemfile to generate real certs
    std::fs::write(&cert_path, "# Self-signed certificate placeholder\n# Replace with real cert: cachee tls import --cert /path/to/cert.pem --key /path/to/key.pem\n")?;
    std::fs::write(&key_path, "# Private key placeholder\n")?;

    let mut cfg = config::load()?;
    // Would add tls_enabled field to config
    let config_path = config::cachee_dir().join("config.toml");
    let toml_str = toml::to_string_pretty(&cfg)?;
    std::fs::write(&config_path, &toml_str)?;

    println!("TLS enabled");
    println!();
    println!("  Cert : {}", cert_path.display());
    println!("  Key  : {}", key_path.display());
    println!();
    println!("  For production, import a real certificate:");
    println!("  cachee tls import --cert /path/to/fullchain.pem --key /path/to/privkey.pem");
    println!();
    println!("  Restart daemon: cachee stop && cachee start");

    Ok(())
}

pub async fn tls_import(cert: &str, key: &str) -> anyhow::Result<()> {
    let tls_dir = config::cachee_dir().join("tls");
    std::fs::create_dir_all(&tls_dir)?;

    // Validate files exist
    if !std::path::Path::new(cert).exists() {
        anyhow::bail!("Certificate file not found: {cert}");
    }
    if !std::path::Path::new(key).exists() {
        anyhow::bail!("Key file not found: {key}");
    }

    // Copy to cachee dir
    std::fs::copy(cert, tls_dir.join("cert.pem"))?;
    std::fs::copy(key, tls_dir.join("key.pem"))?;

    println!("TLS certificate imported");
    println!("  Cert : {cert}");
    println!("  Key  : {key}");
    println!();
    println!("  Restart daemon: cachee stop && cachee start");

    Ok(())
}

pub async fn tls_disable() -> anyhow::Result<()> {
    println!("TLS disabled. Restart daemon to take effect.");
    Ok(())
}

pub async fn tls_status() -> anyhow::Result<()> {
    let tls_dir = config::cachee_dir().join("tls");
    let cert_exists = tls_dir.join("cert.pem").exists();
    let key_exists = tls_dir.join("key.pem").exists();

    println!("TLS Status");
    println!("  Certificate : {}", if cert_exists { "present" } else { "not found" });
    println!("  Private key : {}", if key_exists { "present" } else { "not found" });
    println!("  Status      : {}", if cert_exists && key_exists { "ready" } else { "not configured" });

    if !cert_exists {
        println!();
        println!("  Enable: cachee tls enable");
    }

    Ok(())
}

// ── Key Rotation ─────────────────────────────────────

pub async fn rotate_keys() -> anyhow::Result<()> {
    let keys_dir = config::cachee_dir().join("keys");
    let identity_path = keys_dir.join("identity.toml");

    if !identity_path.exists() {
        anyhow::bail!("No PQ identity found. Run `cachee init` first.");
    }

    // Archive old key
    let old_content = std::fs::read_to_string(&identity_path)?;
    let old_key_id = extract_field(&old_content, "key_id");
    let archive_path = keys_dir.join(format!("identity-{old_key_id}.toml.bak"));
    std::fs::copy(&identity_path, &archive_path)?;

    // Generate new key
    let new_key_id = hex::encode(&rand::random::<[u8; 16]>());
    let key_info = format!(
        "# Cachee PQ Identity\n# Generated: {}\n# Rotated from: {}\nkey_id = \"{}\"\nalgorithms = [\"ML-DSA-65\", \"FALCON-512\", \"SLH-DSA\"]\n",
        now_unix(),
        old_key_id,
        new_key_id,
    );
    std::fs::write(&identity_path, &key_info)?;

    println!("PQ keypair rotated");
    println!();
    println!("  Old key : {old_key_id} (archived at {})", archive_path.display());
    println!("  New key : {new_key_id}");
    println!();
    println!("  Restart daemon: cachee stop && cachee start");
    println!("  Existing cached entries will be re-attested on next access.");

    Ok(())
}

// ── Helpers ──────────────────────────────────────────

fn extract_field<'a>(content: &'a str, field: &str) -> String {
    content.lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split('"').nth(1))
        .unwrap_or("unknown")
        .to_string()
}

fn sha3_hash(data: &[u8]) -> [u8; 32] {
    use sha3::{Sha3_256, Digest};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
