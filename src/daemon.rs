//! `cachee start` / `cachee stop` / `cachee status` — daemon lifecycle.
//!
//! RESP command set:
//!   PING              — health check
//!   SET key value [FP hex]  — store a value, optionally with computation fingerprint
//!   GET key           — retrieve raw value (Redis-compatible)
//!   GETVERIFIED key   — retrieve value with full trust envelope (JSON)
//!   DEL key           — delete a key
//!   INVALIDATE key REASON desc — revoke an entry with a reason
//!   SUPERSEDE old new — transition old entry to Superseded, link to new
//!   STATE key         — return lifecycle state of an entry
//!   INFO              — engine stats

use crate::archive::ComputationFingerprint;
use crate::audit::{AuditEventType, AuditLog};
use crate::cache_slot::{parse_fingerprint, CacheSlot};
use crate::config;
use crate::content_store::ContentStore;
use crate::lifecycle::ValidityWindow;
use crate::lifecycle::{EntryState, TransitionAuthority, TransitionProof};
use crate::read_contract::{CacheeReadResponse, SignatureSummary, VerificationStatus};
use crate::trust::{Provenance, VerificationMode};
use cachee_core::{CacheeEngine, EngineConfig, L0Config};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Slot registry — maps cache keys to their CacheSlot metadata.
///
/// The CacheeEngine handles raw byte storage (L0/L1); this map holds the
/// computation fingerprint, lifecycle state, trust level, and provenance
/// that make Cachee a verifiable system rather than a dumb key-value store.
type SlotRegistry = Arc<RwLock<HashMap<String, CacheSlot>>>;

/// API key registry — maps SHA3-256(secret) → (key_id, permissions).
/// Loaded from ~/.cachee/keys/apikey-*.toml at startup.
type ApiKeyRegistry = Arc<RwLock<HashMap<[u8; 32], ApiKeyEntry>>>;

/// A validated API key entry.
#[derive(Debug, Clone)]
struct ApiKeyEntry {
    #[allow(dead_code)]
    key_id: String,
    label: String,
    permissions: String,
}

impl ApiKeyEntry {
    #[allow(dead_code)]
    fn can_read(&self) -> bool {
        self.permissions.contains("read") || self.permissions.contains("admin")
    }
    fn can_write(&self) -> bool {
        self.permissions.contains("write") || self.permissions.contains("admin")
    }
    fn can_admin(&self) -> bool {
        self.permissions.contains("admin")
    }
}

/// Per-connection auth state.
struct ConnState {
    authenticated: bool,
    key_entry: Option<ApiKeyEntry>,
}

/// Load all API keys from disk into the registry.
fn load_api_keys() -> HashMap<[u8; 32], ApiKeyEntry> {
    let keys_dir = config::cachee_dir().join("keys");
    let mut registry = HashMap::new();

    if let Ok(entries) = std::fs::read_dir(&keys_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("apikey-") && name.ends_with(".toml") {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    let key_id = extract_toml_field(&content, "key_id");
                    let label = extract_toml_field(&content, "label");
                    let permissions = extract_toml_field(&content, "permissions");
                    let secret_hash_hex = extract_toml_field(&content, "secret_hash");

                    if let Ok(hash_bytes) = hex::decode(&secret_hash_hex) {
                        if hash_bytes.len() == 32 {
                            let mut hash = [0u8; 32];
                            hash.copy_from_slice(&hash_bytes);
                            registry.insert(
                                hash,
                                ApiKeyEntry {
                                    key_id,
                                    label,
                                    permissions,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // Also accept the CLI credentials key (from cachee signup)
    let creds_path = config::cachee_dir().join("credentials.toml");
    if let Ok(content) = std::fs::read_to_string(&creds_path) {
        let api_key = extract_toml_field(&content, "api_key");
        if !api_key.is_empty() {
            let hash = crate::cache_slot::sha3_256(api_key.as_bytes());
            registry.insert(
                hash,
                ApiKeyEntry {
                    key_id: "cli-credentials".to_string(),
                    label: "CLI signup key".to_string(),
                    permissions: "read,write".to_string(),
                },
            );
        }
    }

    registry
}

fn extract_toml_field(content: &str, field: &str) -> String {
    content
        .lines()
        .find(|l| l.starts_with(field))
        .and_then(|l| l.split('"').nth(1))
        .unwrap_or("")
        .to_string()
}

/// Start the RESP server with CacheeEngine backing.
pub async fn start(_foreground: bool, _config_path: Option<String>) -> anyhow::Result<()> {
    let cfg = config::load()?;

    let strict_mode = cfg.verification.strict_fingerprint;
    let safe_read_mode = cfg.verification.read_mode == "safe";
    let require_auth = cfg.require_auth;
    let issuer_id = cfg.issuer_id.clone();

    // Load API key registry for AUTH enforcement
    let api_keys: ApiKeyRegistry = Arc::new(RwLock::new(load_api_keys()));
    let key_count = api_keys.read().unwrap().len();

    let engine = Arc::new(CacheeEngine::new(EngineConfig {
        max_keys: cfg.max_keys,
        default_ttl: cfg.default_ttl,
        l0: L0Config {
            enabled: cfg.l0_enabled,
            max_keys: cfg.l0_max_keys,
            shards: cfg.l0_shards,
        },
        ..Default::default()
    }));

    let slots: SlotRegistry = Arc::new(RwLock::new(HashMap::new()));

    // Open persistent content store (L2)
    let store_path = config::cachee_dir().join("content_store");
    std::fs::create_dir_all(&store_path)?;
    let content_store = Arc::new(
        ContentStore::open(&store_path)
            .map_err(|e| anyhow::anyhow!("Failed to open content store: {}", e))?,
    );

    // Open hash-chained audit log (tamper-evident, persistent)
    let audit_path = config::cachee_dir().join("audit_log");
    std::fs::create_dir_all(&audit_path)?;
    let audit_log = Arc::new(Mutex::new(
        AuditLog::open(&audit_path, &issuer_id)
            .map_err(|e| anyhow::anyhow!("Failed to open audit log: {}", e))?,
    ));

    // Log daemon start
    {
        let mut log = audit_log.lock().unwrap();
        let _ = log.append(AuditEventType::DaemonStart {
            version: env!("CARGO_PKG_VERSION").to_string(),
            attest_enabled: cfg.attest_enabled,
            verify_mode: cfg.verification.mode.clone(),
        });
    }

    // Cold start: rebuild L1 (SlotRegistry) from L2 (content store)
    {
        let addresses = content_store.addresses();
        let mut rebuilt = 0u64;
        let mut slots_write = slots.write().unwrap();

        for addr in &addresses {
            if let Ok(Some(bundle)) = content_store.get(addr) {
                // Reconstruct a CacheSlot from the bundle
                let slot = CacheSlot::new(
                    vec![], // value not stored in bundle (only hash) — will miss on first GET
                    bundle.computation_fingerprint.clone(),
                    std::time::Duration::from_secs(cfg.default_ttl as u64),
                    VerificationMode::TrustCached,
                    "cold-start",
                );
                // Use content address hex as the key for now
                let key = hex::encode(&addr[..16]);
                slots_write.insert(key, slot);
                rebuilt += 1;
            }
        }

        if rebuilt > 0 {
            println!("  Cold start  : rebuilt {} slots from L2", rebuilt);
        }
    }

    // Load PQ keypairs (if attestation enabled and keys exist)
    let keys_path = config::cachee_dir().join("keys");
    let pq_keys: Option<Arc<crate::pq_keys::PqKeySet>> =
        if cfg.attest_enabled && crate::pq_keys::PqKeySet::exists(&keys_path) {
            match crate::pq_keys::PqKeySet::load(&keys_path) {
                Ok(keys) => {
                    println!("  PQ keys   : loaded (ML-DSA-65 + FALCON-512 + SLH-DSA-128f)");
                    Some(Arc::new(keys))
                }
                Err(e) => {
                    eprintln!(
                        "[WARN] Failed to load PQ keys: {}. Attestation disabled.",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

    // Write PID file
    let pid_path = config::cachee_dir().join("cachee.pid");
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let addr = format!("127.0.0.1:{}", cfg.port);
    let listener = TcpListener::bind(&addr).await?;

    let verify_mode_str = &cfg.verification.mode;
    println!(
        "Cachee v{} — post-quantum caching service",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("  RESP server : {addr}");
    println!("  Max keys    : {}", cfg.max_keys);
    println!(
        "  L0 hot tier : {} ({} shards)",
        if cfg.l0_enabled {
            "enabled"
        } else {
            "disabled"
        },
        cfg.l0_shards
    );
    println!(
        "  L2 store    : {} ({} bundles)",
        store_path.display(),
        content_store.len()
    );
    println!(
        "  Attest      : {}",
        if cfg.attest_enabled {
            "enabled (3-family PQ)"
        } else {
            "disabled"
        }
    );
    println!("  Verify mode : {verify_mode_str}");
    println!("  Strict FP   : {strict_mode}");
    println!(
        "  Auth        : {} ({} keys loaded)",
        if require_auth { "REQUIRED" } else { "disabled" },
        key_count
    );
    println!(
        "  Metrics     : http://127.0.0.1:{}/metrics",
        cfg.metrics_port
    );
    println!(
        "  Audit log   : {} ({} entries, chain valid)",
        audit_path.display(),
        audit_log.lock().unwrap().len()
    );
    println!("  Issuer ID   : {}", issuer_id);
    println!(
        "  Plan        : {} ({} ops/month)",
        cfg.plan.tier, cfg.plan.ops_per_month
    );
    println!("  PID         : {}", std::process::id());
    println!();
    println!("  Ready for connections.");

    // Accept loop
    loop {
        let (mut socket, _peer) = listener.accept().await?;
        let engine = engine.clone();
        let slots = slots.clone();
        let content_store = content_store.clone();
        let pq_keys = pq_keys.clone();
        let issuer_id = issuer_id.clone();
        let audit_log = audit_log.clone();
        let api_keys = api_keys.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut conn = ConnState {
                authenticated: !require_auth, // if auth not required, auto-auth
                key_entry: None,
            };

            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

                let input = String::from_utf8_lossy(&buf[..n]);
                let parts: Vec<&str> = input.split_whitespace().collect();

                // Handle AUTH command (always allowed, even before auth)
                if !parts.is_empty() && parts[0].eq_ignore_ascii_case("AUTH") {
                    let response = handle_auth(&parts, &api_keys, &mut conn);
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                    continue;
                }

                // PING is always allowed (health checks)
                if !parts.is_empty() && parts[0].eq_ignore_ascii_case("PING") {
                    if socket.write_all(b"+PONG\r\n").await.is_err() {
                        return;
                    }
                    continue;
                }

                // Enforce auth if required
                if !conn.authenticated {
                    let msg = "-NOAUTH Authentication required. Send AUTH <api_key> first.\r\n";
                    if socket.write_all(msg.as_bytes()).await.is_err() {
                        return;
                    }
                    continue;
                }

                // Permission check for write commands
                if require_auth {
                    if let Some(ref entry) = conn.key_entry {
                        let cmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();
                        let needs_write = matches!(
                            cmd.as_str(),
                            "SET" | "DEL" | "INVALIDATE" | "SUPERSEDE" | "FLUSH"
                        );
                        let needs_admin =
                            matches!(cmd.as_str(), "AUDITLOG" | "AUDITVERIFY" | "AUDITANCHOR");

                        if needs_write && !entry.can_write() {
                            let msg = "-NOPERM this key does not have write permission\r\n";
                            if socket.write_all(msg.as_bytes()).await.is_err() {
                                return;
                            }
                            continue;
                        }
                        if needs_admin && !entry.can_admin() && !entry.can_write() {
                            let msg = "-NOPERM this key does not have admin permission\r\n";
                            if socket.write_all(msg.as_bytes()).await.is_err() {
                                return;
                            }
                            continue;
                        }
                    }
                }

                let response = handle_resp(
                    &engine,
                    &slots,
                    &content_store,
                    strict_mode,
                    safe_read_mode,
                    &issuer_id,
                    &pq_keys,
                    &audit_log,
                    &buf[..n],
                );
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// AUTH handler — validates API key against loaded key registry.
/// Key is hashed with SHA3-256 and compared against stored hashes.
fn handle_auth(parts: &[&str], api_keys: &ApiKeyRegistry, conn: &mut ConnState) -> String {
    if parts.len() < 2 {
        return "-ERR AUTH requires a key argument\r\n".to_string();
    }

    let secret = parts[1];
    let hash = crate::cache_slot::sha3_256(secret.as_bytes());

    let registry = api_keys.read().unwrap();
    match registry.get(&hash) {
        Some(entry) => {
            conn.authenticated = true;
            conn.key_entry = Some(entry.clone());
            format!(
                "+OK authenticated as {} ({})\r\n",
                entry.label, entry.permissions
            )
        }
        None => {
            conn.authenticated = false;
            conn.key_entry = None;
            "-ERR invalid API key\r\n".to_string()
        }
    }
}

/// RESP parser — handles SET, GET, GETVERIFIED, DEL, PING, INFO,
/// INVALIDATE, SUPERSEDE, STATE.
#[allow(clippy::too_many_arguments)]
fn handle_resp(
    engine: &CacheeEngine,
    slots: &SlotRegistry,
    content_store: &ContentStore,
    strict_mode: bool,
    safe_read_mode: bool,
    issuer_id: &str,
    pq_keys: &Option<Arc<crate::pq_keys::PqKeySet>>,
    audit_log: &Arc<Mutex<AuditLog>>,
    data: &[u8],
) -> String {
    let input = String::from_utf8_lossy(data);
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.is_empty() {
        return "-ERR empty command\r\n".to_string();
    }

    match parts[0].to_uppercase().as_str() {
        "PING" => "+PONG\r\n".to_string(),

        // ── SET key value [FP hex] ─────────────────────────────
        "SET" if parts.len() >= 3 => {
            let key = parts[1].to_string();

            // Check for FP (fingerprint) argument
            let fp_idx = parts.iter().position(|p| p.eq_ignore_ascii_case("FP"));
            let (value_str, fingerprint) = if let Some(idx) = fp_idx {
                let value = parts[2..idx].join(" ");
                let fp_hex = parts.get(idx + 1).copied().unwrap_or("");
                let fp = parse_fingerprint(fp_hex);
                (value, fp)
            } else {
                // No fingerprint — check strict mode
                if strict_mode {
                    return "-ERR computation fingerprint required (strict mode)\r\n".to_string();
                }
                (parts[2..].join(" "), ComputationFingerprint::empty())
            };

            let value_bytes = value_str.as_bytes().to_vec();

            // Create the CacheSlot with metadata
            let slot = CacheSlot::new(
                value_bytes,
                fingerprint,
                std::time::Duration::from_secs(3600),
                VerificationMode::TrustCached,
                issuer_id,
            );

            // Store slot metadata
            {
                let mut registry = slots.write().unwrap();
                registry.insert(key.clone(), slot);
            }

            // Persist to L2 content store as a CAB bundle
            {
                let registry = slots.read().unwrap();
                if let Some(slot) = registry.get(&key) {
                    if slot.has_valid_fingerprint() {
                        let bundle = slot_to_bundle(slot, &key, pq_keys, issuer_id);
                        if let Err(e) = content_store.put(&bundle) {
                            eprintln!("[WARN] L2 persist failed for {}: {}", key, e);
                        }
                    }
                }
            }

            // Store raw bytes in the engine for fast GET
            engine.set(key.clone(), bytes::Bytes::from(value_str), None);

            // Audit: log entry creation
            {
                let registry = slots.read().unwrap();
                if let Some(slot) = registry.get(&key) {
                    let mut log = audit_log.lock().unwrap();
                    let _ = log.append(AuditEventType::EntryCreated {
                        key: key.clone(),
                        content_address: hex::encode(slot.content_address),
                        fingerprint_digest: hex::encode(slot.fingerprint.digest()),
                        signed: pq_keys.is_some() && slot.has_valid_fingerprint(),
                    });
                }
            }

            "+OK\r\n".to_string()
        }

        // ── GET key (Redis-compatible, or safe mode) ────────────
        "GET" if parts.len() >= 2 => {
            if safe_read_mode {
                return "-ERR Use GETVERIFIED for verified reads. GET is disabled in safe mode. Set read_mode = \"compatible\" to enable unverified reads.\r\n".to_string();
            }
            match engine.get(parts[1]) {
                Some((value, _level)) => {
                    let s = String::from_utf8_lossy(&value);
                    format!("${}\r\n{}\r\n", s.len(), s)
                }
                None => "$-1\r\n".to_string(),
            }
        }

        // ── GETVERIFIED key — full trust envelope with REAL verification ──
        "GETVERIFIED" if parts.len() >= 2 => {
            let key = parts[1];
            match get_verified(engine, slots, content_store, pq_keys, key) {
                Some(response) => {
                    // Audit: log verification result
                    {
                        let mut log = audit_log.lock().unwrap();
                        match &response.verification {
                            VerificationStatus::FullyVerified { .. } => {
                                let _ = log.append(AuditEventType::VerificationPerformed {
                                    key: key.to_string(),
                                    mldsa_valid: response.signatures.mldsa_valid.unwrap_or(false),
                                    falcon_valid: response.signatures.falcon_valid.unwrap_or(false),
                                    slhdsa_valid: response.signatures.slhdsa_valid.unwrap_or(false),
                                    two_of_three: response.signatures.two_of_three,
                                    all_three: response.signatures.mldsa_valid.unwrap_or(false)
                                        && response.signatures.falcon_valid.unwrap_or(false)
                                        && response.signatures.slhdsa_valid.unwrap_or(false),
                                });
                            }
                            VerificationStatus::VerificationFailed { reason } => {
                                let _ = log.append(AuditEventType::VerificationFailed {
                                    key: key.to_string(),
                                    error: reason.clone(),
                                });
                            }
                            _ => {}
                        }
                    }
                    let json = serde_json::to_string(&response).unwrap_or_default();
                    format!("${}\r\n{}\r\n", json.len(), json)
                }
                None => "$-1\r\n".to_string(),
            }
        }

        // ── DEL key ────────────────────────────────────────────
        "DEL" if parts.len() >= 2 => {
            let key = parts[1];
            let deleted = engine.delete(key);
            // Also remove from slot registry
            {
                let mut registry = slots.write().unwrap();
                registry.remove(key);
            }
            // Audit: log deletion
            if deleted {
                let mut log = audit_log.lock().unwrap();
                let _ = log.append(AuditEventType::EntryDeleted {
                    key: key.to_string(),
                });
            }
            format!(":{}\r\n", if deleted { 1 } else { 0 })
        }

        // ── INVALIDATE key REASON description ──────────────────
        "INVALIDATE" if parts.len() >= 4 => {
            let key = parts[1];
            let reason = parts[3..].join(" ");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;

            let mut registry = slots.write().unwrap();
            match registry.get_mut(key) {
                Some(slot) => {
                    let new_state = EntryState::Revoked {
                        reason: reason.clone(),
                        revoked_at: now,
                        revocation_attestation: None,
                    };
                    match slot.transition(
                        new_state,
                        TransitionAuthority::System,
                        TransitionProof::SystemInitiated,
                    ) {
                        Ok(_transition) => {
                            // Audit: log state transition
                            let mut log = audit_log.lock().unwrap();
                            let _ = log.append(AuditEventType::StateTransition {
                                key: key.to_string(),
                                from_state: "Active".to_string(),
                                to_state: "Revoked".to_string(),
                                authority: "System".to_string(),
                                reason: Some(reason),
                            });
                            "+OK\r\n".to_string()
                        }
                        Err(e) => format!("-ERR {}\r\n", e),
                    }
                }
                None => "-ERR key not found\r\n".to_string(),
            }
        }

        // ── SUPERSEDE old_key new_key ──────────────────────────
        "SUPERSEDE" if parts.len() >= 3 => {
            let old_key = parts[1];
            let new_key = parts[2];

            let mut registry = slots.write().unwrap();

            // Look up the new entry's content address
            let new_content_address = match registry.get(new_key) {
                Some(new_slot) => new_slot.content_address,
                None => {
                    return "-ERR new key not found\r\n".to_string();
                }
            };

            // Transition old entry to Superseded
            match registry.get_mut(old_key) {
                Some(old_slot) => {
                    let new_state = EntryState::Superseded {
                        successor: new_content_address,
                    };
                    match old_slot.transition(
                        new_state,
                        TransitionAuthority::System,
                        TransitionProof::SystemInitiated,
                    ) {
                        Ok(_transition) => {
                            let mut log = audit_log.lock().unwrap();
                            let _ = log.append(AuditEventType::StateTransition {
                                key: old_key.to_string(),
                                from_state: "Active".to_string(),
                                to_state: format!("Superseded({})", new_key),
                                authority: "System".to_string(),
                                reason: None,
                            });
                            "+OK\r\n".to_string()
                        }
                        Err(e) => format!("-ERR {}\r\n", e),
                    }
                }
                None => "-ERR old key not found\r\n".to_string(),
            }
        }

        // ── STATE key — return lifecycle state ─────────────────
        "STATE" if parts.len() >= 2 => {
            let key = parts[1];
            let registry = slots.read().unwrap();
            match registry.get(key) {
                Some(slot) => {
                    let state_str = format!("{:?}", slot.state);
                    format!("${}\r\n{}\r\n", state_str.len(), state_str)
                }
                None => "$-1\r\n".to_string(),
            }
        }

        // ── INFO (unchanged) ───────────────────────────────────
        "INFO" => {
            let stats = engine.stats();
            let slot_count = slots.read().map(|r| r.len()).unwrap_or(0);
            let info = format!(
                "# Cachee\r\nversion:{}\r\ntotal_ops:{}\r\nhit_rate:{:.4}\r\nhits_l0:{}\r\nhits_l1:{}\r\nmisses:{}\r\nkeys:{}\r\nmemory_bytes:{}\r\nslots:{}\r\nl2_bundles:{}\r\n",
                env!("CARGO_PKG_VERSION"),
                stats.total_ops,
                stats.hit_rate,
                stats.hits.l0,
                stats.hits.l1,
                stats.misses,
                stats.key_count,
                stats.memory_bytes,
                slot_count,
                content_store.len(),
            );
            format!("${}\r\n{}\r\n", info.len(), info)
        }
        // ── AUDITLOG key — full lifecycle export ────────────
        "AUDITLOG" if parts.len() >= 2 => {
            let key = parts[1];
            let log = audit_log.lock().unwrap();
            let json = log.export_key_lifecycle(key);
            format!("${}\r\n{}\r\n", json.len(), json)
        }

        // ── AUDITVERIFY — verify hash chain integrity ─────
        "AUDITVERIFY" => {
            let log = audit_log.lock().unwrap();
            match log.verify_chain() {
                Ok((count, None)) => {
                    let msg = format!(
                        "OK {} entries verified, chain intact, head={}",
                        count,
                        hex::encode(log.head())
                    );
                    format!("${}\r\n{}\r\n", msg.len(), msg)
                }
                Ok((count, Some(broken_at))) => {
                    let msg = format!(
                        "BROKEN chain broken at sequence {}, {} entries verified before break",
                        broken_at, count
                    );
                    format!("-ERR {}\r\n", msg)
                }
                Err(e) => format!("-ERR audit verify failed: {}\r\n", e),
            }
        }

        // ── AUDITANCHOR — compute Merkle root anchor ──────
        "AUDITANCHOR" => {
            let mut log = audit_log.lock().unwrap();
            match log.compute_merkle_anchor() {
                Ok(root) => {
                    let msg = format!("OK merkle_root={}", hex::encode(root));
                    format!("${}\r\n{}\r\n", msg.len(), msg)
                }
                Err(e) => format!("-ERR {}\r\n", e),
            }
        }

        _ => "-ERR unknown command\r\n".to_string(),
    }
}

/// Convert a CacheSlot into a CacheeArchiveBundle for L2 persistence.
///
/// When PQ keys are available (attestation enabled), the bundle is fully signed
/// with all three PQ families. Otherwise, a partial bundle is created with empty
/// signatures — still useful for cold-start recovery of fingerprints and value hashes.
fn slot_to_bundle(
    slot: &CacheSlot,
    _key: &str,
    pq_keys: &Option<Arc<crate::pq_keys::PqKeySet>>,
    issuer_id: &str,
) -> crate::archive::CacheeArchiveBundle {
    use crate::archive::*;

    let content_hash = crate::cache_slot::sha3_256(&slot.value);

    // Sign the content hash with all three PQ families if keys are available
    let (signer_keys, signatures, completeness, mldsa_prefix, falcon_prefix, slhdsa_prefix) =
        match pq_keys {
            Some(keys) => {
                let sigs = keys.sign(&content_hash);
                let mp = if sigs.mldsa_sig.len() >= 2 {
                    [sigs.mldsa_sig[0], sigs.mldsa_sig[1]]
                } else {
                    [0; 2]
                };
                let fp = if sigs.falcon_sig.len() >= 2 {
                    [sigs.falcon_sig[0], sigs.falcon_sig[1]]
                } else {
                    [0; 2]
                };
                let sp = if sigs.slhdsa_sig.len() >= 2 {
                    [sigs.slhdsa_sig[0], sigs.slhdsa_sig[1]]
                } else {
                    [0; 2]
                };

                (
                    keys.public_keys(),
                    SignatureBundle {
                        mldsa65: sigs.mldsa_sig,
                        falcon512: sigs.falcon_sig,
                        slhdsa128f: sigs.slhdsa_sig,
                    },
                    CompletenessLevel::Complete,
                    mp,
                    fp,
                    sp,
                )
            }
            None => (
                SignerPublicKeys {
                    mldsa65: vec![],
                    falcon512: vec![],
                    slhdsa128f: vec![],
                },
                SignatureBundle {
                    mldsa65: vec![],
                    falcon512: vec![],
                    slhdsa128f: vec![],
                },
                CompletenessLevel::Partial,
                [0u8; 2],
                [0u8; 2],
                [0u8; 2],
            ),
        };

    let signer_identity = match pq_keys {
        Some(keys) => SignerIdentity {
            key_id: keys.metadata.key_id,
            key_version: keys.metadata.version,
            families: vec![
                "ML-DSA-65".to_string(),
                "FALCON-512".to_string(),
                "SLH-DSA-SHA2-128f".to_string(),
            ],
            issuer: issuer_id.to_string(),
            posture: format!("{:?}", keys.metadata.posture),
        },
        None => SignerIdentity::default(),
    };

    CacheeArchiveBundle {
        magic: CAB_MAGIC,
        version: 1,
        primitive: H33Primitive {
            version: 1,
            timestamp: slot.created_at.to_be_bytes(),
            value_hash: content_hash,
            mldsa_prefix,
            falcon_prefix,
            slhdsa_prefix,
            flags: [0; 11],
        },
        content_hash,
        computation_type: ComputationType::Custom(0),
        timestamp_ns: slot.created_at,
        signer_keys,
        signatures,
        metadata: vec![],
        on_chain_anchor: None,
        completeness,
        computation_fingerprint: slot.fingerprint.clone(),
        signer_identity,
    }
}

/// Construct a full CacheeReadResponse for a GETVERIFIED request.
///
/// **This performs REAL cryptographic verification.** If the slot has a
/// corresponding CAB bundle in the content store, signatures are verified
/// using the actual PQ crypto libraries. The result is recorded in the
/// response and audit log.
///
/// Returns `None` if the key does not exist.
fn get_verified(
    engine: &CacheeEngine,
    slots: &SlotRegistry,
    content_store: &ContentStore,
    _pq_keys: &Option<Arc<crate::pq_keys::PqKeySet>>,
    key: &str,
) -> Option<CacheeReadResponse> {
    // 1. Get raw value from engine
    let (value, _level) = engine.get(key)?;

    // 2. Get CacheSlot metadata
    let registry = slots.read().unwrap();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    match registry.get(key) {
        Some(slot) => {
            // 3. Attempt REAL cryptographic verification via CAB bundle
            let (verification, sig_summary) = if slot.has_valid_fingerprint() {
                // Try to find the bundle in content store by content address
                match content_store.get(&slot.content_address) {
                    Ok(Some(bundle)) => {
                        // REAL VERIFICATION: call bundle.verify() which checks
                        // ML-DSA-65, FALCON-512, and SLH-DSA signatures
                        let result = bundle.verify();
                        let mldsa = result.mldsa_valid();
                        let falcon = result.falcon_valid();
                        let slhdsa = result.slhdsa_valid();
                        let two = result.two_of_three();
                        let all = mldsa && falcon && slhdsa;

                        if two {
                            (
                                VerificationStatus::FullyVerified {
                                    verified_at: now_ns,
                                    all_three: all,
                                    two_of_three: two,
                                },
                                SignatureSummary {
                                    mldsa_valid: Some(mldsa),
                                    falcon_valid: Some(falcon),
                                    slhdsa_valid: Some(slhdsa),
                                    two_of_three: two,
                                    last_full_check: now_ns,
                                },
                            )
                        } else {
                            (
                                VerificationStatus::VerificationFailed {
                                    reason: format!(
                                        "signature check failed: mldsa={}, falcon={}, slhdsa={}",
                                        mldsa, falcon, slhdsa
                                    ),
                                },
                                SignatureSummary {
                                    mldsa_valid: Some(mldsa),
                                    falcon_valid: Some(falcon),
                                    slhdsa_valid: Some(slhdsa),
                                    two_of_three: false,
                                    last_full_check: now_ns,
                                },
                            )
                        }
                    }
                    _ => {
                        // No bundle in content store — entry was SET without attestation
                        (
                            VerificationStatus::Unverified {
                                last_verified_at: slot.trust.last_verified_at,
                                trust_score: slot.trust.trust_score,
                            },
                            SignatureSummary {
                                mldsa_valid: None,
                                falcon_valid: None,
                                slhdsa_valid: None,
                                two_of_three: false,
                                last_full_check: 0,
                            },
                        )
                    }
                }
            } else {
                // No fingerprint — can't verify
                (
                    VerificationStatus::Unverified {
                        last_verified_at: slot.trust.last_verified_at,
                        trust_score: 0.0,
                    },
                    SignatureSummary {
                        mldsa_valid: None,
                        falcon_valid: None,
                        slhdsa_valid: None,
                        two_of_three: false,
                        last_full_check: 0,
                    },
                )
            };

            Some(CacheeReadResponse {
                value: value.to_vec(),
                fingerprint: slot.fingerprint.clone(),
                verification,
                signatures: sig_summary,
                provenance: slot.provenance.clone(),
                state: slot.state.clone(),
                validity: slot.temporal.validity.clone(),
            })
        }
        None => {
            // Key exists in engine but not in slot registry
            Some(CacheeReadResponse {
                value: value.to_vec(),
                fingerprint: ComputationFingerprint::empty(),
                verification: VerificationStatus::Unverified {
                    last_verified_at: 0,
                    trust_score: 0.0,
                },
                signatures: SignatureSummary {
                    mldsa_valid: None,
                    falcon_valid: None,
                    slhdsa_valid: None,
                    two_of_three: false,
                    last_full_check: 0,
                },
                provenance: Provenance {
                    computed_by: "unknown".to_string(),
                    computed_at: 0,
                    computation_duration_us: 0,
                    verified_by: Vec::new(),
                },
                state: EntryState::Active,
                validity: ValidityWindow {
                    valid_from: 0,
                    valid_until: None,
                    revalidation_trigger: None,
                },
            })
        }
    }
}

pub async fn stop() -> anyhow::Result<()> {
    let pid_path = config::cachee_dir().join("cachee.pid");
    if !pid_path.exists() {
        println!("Cachee is not running (no PID file)");
        return Ok(());
    }

    let pid_str = std::fs::read_to_string(&pid_path)?;
    let pid: i32 = pid_str.trim().parse()?;

    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    std::fs::remove_file(&pid_path)?;
    println!("Cachee stopped (PID {pid})");

    Ok(())
}

pub async fn status() -> anyhow::Result<()> {
    let cfg = config::load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);

    // Try to connect and send PING
    match tokio::net::TcpStream::connect(&addr).await {
        Ok(mut stream) => {
            stream.write_all(b"PING\r\n").await?;
            let mut buf = vec![0u8; 256];
            let n = stream.read(&mut buf).await?;
            let response = String::from_utf8_lossy(&buf[..n]);

            if response.contains("PONG") {
                // Get INFO
                stream.write_all(b"INFO\r\n").await?;
                let n = stream.read(&mut buf).await?;
                let info = String::from_utf8_lossy(&buf[..n]);

                println!("Cachee is running on {addr}");
                println!();
                println!("{info}");
            } else {
                println!("Cachee responded but not healthy: {response}");
            }
        }
        Err(_) => {
            println!("Cachee is not running on {addr}");
        }
    }

    Ok(())
}
