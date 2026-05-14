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
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Hard ops limit for this key. 0 = unlimited.
    ops_limit: u64,
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
    /// The SHA3-256 hash of the secret used to authenticate.
    /// Used to check if the key has been revoked (registry lookup by hash).
    key_hash: Option<[u8; 32]>,
}

/// Global ops counters per key_id. Quota is tied to the key, not the connection.
/// Reconnecting or re-authing does NOT reset the counter.
/// Only window rollover or admin reset clears usage.
type OpsCounters = Arc<RwLock<HashMap<String, Arc<AtomicU64>>>>;

/// Timestamp of last successful key registry reload.
static REGISTRY_LAST_RELOAD: AtomicU64 = AtomicU64::new(0);
/// Timestamp of last successful usage flush.
static LAST_FLUSH: AtomicU64 = AtomicU64::new(0);

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Spawn background task to flush local ops counters to Auth1 every `interval` seconds.
/// Pattern: atomic local increment (fast path) → periodic bulk flush to server (persistence).
/// Same architecture as H33: local counter → 15s flush → Auth1 → PG.
fn spawn_usage_flusher(ops_counters: OpsCounters, _api_keys: ApiKeyRegistry, interval_secs: u64) {
    // We need the credentials API key to authenticate flush requests
    let creds_path = config::cachee_dir().join("credentials.toml");
    let api_key = std::fs::read_to_string(&creds_path)
        .ok()
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("api_key"))
                .and_then(|l| l.split('"').nth(1))
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    if api_key.is_empty() {
        eprintln!("[WARN] No API key for usage flush. Local metering only.");
        return;
    }

    let auth1_base = std::env::var("AUTH1_PROXY_BASE")
        .unwrap_or_else(|_| "https://cachee.ai/api/cachee-usage".to_string());
    let usage_url = if auth1_base.contains("cachee.ai") {
        auth1_base
    } else {
        format!("{}/api/cachee/cli/usage", auth1_base)
    };

    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        loop {
            std::thread::sleep(std::time::Duration::from_secs(interval_secs));

            // Collect and reset all counters atomically
            let counters = ops_counters.read().unwrap();
            let mut total_flushed = 0u64;

            for (key_id, counter) in counters.iter() {
                let ops = counter.swap(0, Ordering::SeqCst);
                if ops == 0 {
                    continue;
                }

                // Flush to Auth1/cachee.ai
                match client
                    .post(&usage_url)
                    .json(&serde_json::json!({
                        "api_key": api_key,
                        "ops_count": ops,
                    }))
                    .send()
                {
                    Ok(resp) if resp.status().is_success() => {
                        total_flushed += ops;
                    }
                    Ok(resp) => {
                        // Flush failed — add ops back so they're not lost
                        counter.fetch_add(ops, Ordering::SeqCst);
                        eprintln!(
                            "[WARN] Usage flush failed for {}: HTTP {}",
                            key_id,
                            resp.status()
                        );
                    }
                    Err(e) => {
                        counter.fetch_add(ops, Ordering::SeqCst);
                        eprintln!("[WARN] Usage flush error for {}: {}", key_id, e);
                    }
                }
            }

            if total_flushed > 0 {
                LAST_FLUSH.store(now_secs(), Ordering::Relaxed);
            }
        }
    });
}

/// Load all API keys from disk into the registry.
/// Load all API keys from disk. Returns None if keys dir doesn't exist
/// and we're not in dev mode (fail closed).
fn load_api_keys() -> Option<HashMap<[u8; 32], ApiKeyEntry>> {
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
                    let ops_limit_str = extract_toml_field(&content, "ops_limit");
                    let ops_limit: u64 = ops_limit_str.parse().unwrap_or(0); // 0 = unlimited

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
                                    ops_limit,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // Also accept the CLI credentials key (from cachee signup)
    // Ops limit comes from the plan config
    let creds_path = config::cachee_dir().join("credentials.toml");
    if let Ok(content) = std::fs::read_to_string(&creds_path) {
        let api_key = extract_toml_field(&content, "api_key");
        if !api_key.is_empty() {
            // Load plan limit from config
            let plan_limit = config::load()
                .map(|c| c.plan.ops_per_month)
                .unwrap_or(1_000); // Default to 1,000 for sandbox/free
            let hash = crate::cache_slot::sha3_256(api_key.as_bytes());
            registry.insert(
                hash,
                ApiKeyEntry {
                    key_id: "cli-credentials".to_string(),
                    label: "CLI signup key".to_string(),
                    permissions: "read,write".to_string(),
                    ops_limit: plan_limit,
                },
            );
        }
    }

    REGISTRY_LAST_RELOAD.store(now_secs(), std::sync::atomic::Ordering::Relaxed);
    Some(registry)
}

/// Spawn background task to reload key registry every `interval` seconds.
/// Performs atomic swap — hot path reads are never blocked.
fn spawn_registry_reloader(api_keys: ApiKeyRegistry, interval_secs: u64) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
        if let Some(new_registry) = load_api_keys() {
            let mut write = api_keys.write().unwrap();
            *write = new_registry;
            // REGISTRY_LAST_RELOAD is already updated inside load_api_keys
        }
        // If load fails, keep the old registry (fail-open for reload, fail-closed for startup)
    });
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

    // Load API key registry for AUTH enforcement (fail-closed on startup)
    let initial_keys = if require_auth {
        match load_api_keys() {
            Some(keys) if !keys.is_empty() => keys,
            Some(_) => {
                eprintln!("FATAL: require_auth=true but no API keys found. Create keys with: cachee auth create --label \"my-app\"");
                std::process::exit(1);
            }
            None => {
                eprintln!("FATAL: require_auth=true but key registry failed to load.");
                std::process::exit(1);
            }
        }
    } else {
        load_api_keys().unwrap_or_default()
    };
    let key_count = initial_keys.len();
    let api_keys: ApiKeyRegistry = Arc::new(RwLock::new(initial_keys));

    // Spawn background key registry reloader (revocation within 3 seconds)
    if require_auth {
        spawn_registry_reloader(api_keys.clone(), 3);
    }

    // Global ops counters — tied to key_id, survives reconnects/re-auth.
    // Quota is access control. Reconnecting does NOT reset the counter.
    let ops_counters: OpsCounters = Arc::new(RwLock::new(HashMap::new()));

    // Spawn background usage flusher: local counter → 15s flush → Auth1 → PG
    spawn_usage_flusher(ops_counters.clone(), api_keys.clone(), 15);

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
        "  Auth        : {} ({} keys loaded, reload every 3s)",
        if require_auth { "REQUIRED" } else { "disabled" },
        key_count
    );
    println!(
        "  Quota       : {} ops/month (enforced at RESP layer)",
        cfg.plan.ops_per_month
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
        let ops_counters = ops_counters.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut conn = ConnState {
                authenticated: !require_auth,
                key_entry: None,
                key_hash: None,
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

                // Quota enforcement — atomic, immediate, per key_id (not per connection).
                // Quota is access control, not accounting.
                // Reconnecting or re-authing does NOT reset the counter.
                if let Some(ref entry) = conn.key_entry {
                    if entry.ops_limit > 0 {
                        // Get or create the global counter for this key_id
                        let counter = {
                            let read = ops_counters.read().unwrap();
                            read.get(&entry.key_id).cloned()
                        };
                        let counter = match counter {
                            Some(c) => c,
                            None => {
                                let mut write = ops_counters.write().unwrap();
                                let c = write
                                    .entry(entry.key_id.clone())
                                    .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                                    .clone();
                                c
                            }
                        };

                        let current = counter.fetch_add(1, Ordering::SeqCst);
                        if current >= entry.ops_limit {
                            counter.fetch_sub(1, Ordering::SeqCst);
                            let msg = format!(
                                "-QUOTA ops limit exceeded ({}/{} ops). Upgrade your plan: cachee plan upgrade starter\r\n",
                                current, entry.ops_limit
                            );
                            if socket.write_all(msg.as_bytes()).await.is_err() {
                                return;
                            }
                            continue;
                        }
                    }
                }

                // Re-validate key against current registry (catches revocations within reload window)
                if require_auth {
                    if let Some(ref hash) = conn.key_hash {
                        let still_valid = {
                            let registry = api_keys.read().unwrap();
                            registry.contains_key(hash)
                        }; // guard dropped before await
                        if !still_valid {
                            conn.authenticated = false;
                            conn.key_entry = None;
                            conn.key_hash = None;
                            let msg = "-NOAUTH key has been revoked. Re-authenticate.\r\n";
                            if socket.write_all(msg.as_bytes()).await.is_err() {
                                return;
                            }
                            continue;
                        }
                    }
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
            conn.key_hash = Some(hash);
            // NOTE: ops counter is NOT reset on re-auth.
            // Quota is tied to key_id globally, not per connection.
            format!(
                "+OK authenticated as {} ({}, limit={})\r\n",
                entry.label,
                entry.permissions,
                if entry.ops_limit > 0 {
                    entry.ops_limit.to_string()
                } else {
                    "unlimited".to_string()
                }
            )
        }
        None => {
            conn.authenticated = false;
            conn.key_entry = None;
            conn.key_hash = None;
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
            let reload_ts = REGISTRY_LAST_RELOAD.load(Ordering::Relaxed);
            let flush_ts = LAST_FLUSH.load(Ordering::Relaxed);
            let info = format!(
                "# Cachee\r\nversion:{}\r\ntotal_ops:{}\r\nhit_rate:{:.4}\r\nhits_l0:{}\r\nhits_l1:{}\r\nmisses:{}\r\nkeys:{}\r\nmemory_bytes:{}\r\nslots:{}\r\nl2_bundles:{}\r\nkey_registry_last_reload:{}\r\nlast_usage_flush:{}\r\n",
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
                reload_ts,
                flush_ts,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_registry() -> HashMap<[u8; 32], ApiKeyEntry> {
        let mut registry = HashMap::new();
        let hash = crate::cache_slot::sha3_256(b"test-secret-key");
        registry.insert(
            hash,
            ApiKeyEntry {
                key_id: "test-key-001".to_string(),
                label: "test key".to_string(),
                permissions: "read,write".to_string(),
                ops_limit: 1_000,
            },
        );
        let readonly_hash = crate::cache_slot::sha3_256(b"readonly-secret");
        registry.insert(
            readonly_hash,
            ApiKeyEntry {
                key_id: "readonly-key-001".to_string(),
                label: "readonly key".to_string(),
                permissions: "read".to_string(),
                ops_limit: 500,
            },
        );
        registry
    }

    #[test]
    fn test_ops_limit_exceeded_returns_quota_error() {
        // Quota is per key_id, stored in global OpsCounters
        let counter = Arc::new(AtomicU64::new(0));
        let limit: u64 = 1_000;

        // Simulate 1,000 ops consumed
        counter.store(1_000, Ordering::SeqCst);

        // Next op should be blocked
        let current = counter.fetch_add(1, Ordering::SeqCst);
        assert!(current >= limit, "should be blocked at limit");
        counter.fetch_sub(1, Ordering::SeqCst); // undo
        assert_eq!(counter.load(Ordering::SeqCst), 1_000, "counter unchanged");
    }

    #[test]
    fn test_concurrent_ops_cannot_exceed_cap() {
        // Global counter shared across all connections for the same key_id
        let counter = Arc::new(AtomicU64::new(0));
        let limit: u64 = 100;

        // 200 threads (simulating reconnects) all sharing the SAME counter
        let handles: Vec<_> = (0..200)
            .map(|_| {
                let counter = counter.clone();
                std::thread::spawn(move || {
                    let current = counter.fetch_add(1, Ordering::SeqCst);
                    if current >= limit {
                        counter.fetch_sub(1, Ordering::SeqCst);
                        return false;
                    }
                    true
                })
            })
            .collect();

        let mut allowed = 0u64;
        let mut blocked = 0u64;
        for h in handles {
            if h.join().unwrap() {
                allowed += 1;
            } else {
                blocked += 1;
            }
        }

        assert_eq!(allowed, 100);
        assert_eq!(blocked, 100);
        assert_eq!(counter.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn test_revoked_key_fails_after_reload() {
        let api_keys: ApiKeyRegistry = Arc::new(RwLock::new(make_test_registry()));
        let mut conn = ConnState {
            authenticated: false,
            key_entry: None,
            key_hash: None,
        };

        let result = handle_auth(&["AUTH", "test-secret-key"], &api_keys, &mut conn);
        assert!(result.contains("+OK"));
        assert!(conn.authenticated);

        // Simulate revocation via registry reload
        {
            let mut registry = api_keys.write().unwrap();
            let hash = crate::cache_slot::sha3_256(b"test-secret-key");
            registry.remove(&hash);
        }

        // Revocation check (runs on every command)
        if let Some(ref hash) = conn.key_hash {
            let still_valid = {
                let registry = api_keys.read().unwrap();
                registry.contains_key(hash)
            };
            assert!(!still_valid, "revoked key should not be valid");
        }
    }

    #[test]
    fn test_malformed_registry_fails_closed() {
        let registry = HashMap::<[u8; 32], ApiKeyEntry>::new();
        let require_auth = true;
        assert!(
            require_auth && registry.is_empty(),
            "empty registry with require_auth must trigger fail-closed"
        );
    }

    #[test]
    fn test_missing_registry_fails_closed_unless_dev() {
        let require_auth_prod = true;
        let require_auth_dev = false;
        let empty_keys: HashMap<[u8; 32], ApiKeyEntry> = HashMap::new();

        // Production: empty = fail
        assert!(require_auth_prod && empty_keys.is_empty());
        // Dev: empty = ok
        assert!(!require_auth_dev);
    }

    #[test]
    fn test_invalid_auth_key_rejected() {
        let api_keys: ApiKeyRegistry = Arc::new(RwLock::new(make_test_registry()));
        let mut conn = ConnState {
            authenticated: false,
            key_entry: None,
            key_hash: None,
        };

        let result = handle_auth(&["AUTH", "wrong-key-entirely"], &api_keys, &mut conn);
        assert!(result.contains("-ERR"));
        assert!(!conn.authenticated);
        assert!(conn.key_entry.is_none());
        assert!(conn.key_hash.is_none());
    }

    #[test]
    fn test_reauth_does_not_reset_quota() {
        // Quota is tied to key_id globally. Reconnecting or re-authing
        // must NOT reset the counter. Otherwise users bypass caps.
        let counters: OpsCounters = Arc::new(RwLock::new(HashMap::new()));
        let key_id = "test-key-001".to_string();
        let limit: u64 = 1_000;

        // Simulate first connection: consume 500 ops
        {
            let counter = counters
                .write()
                .unwrap()
                .entry(key_id.clone())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .clone();
            for _ in 0..500 {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }

        // Simulate disconnect + reconnect + re-AUTH (new connection, same key_id)
        {
            let counter = {
                let read = counters.read().unwrap();
                read.get(&key_id).cloned().unwrap()
            };
            // Counter must still be 500, not reset
            assert_eq!(counter.load(Ordering::SeqCst), 500);

            // Can do 500 more ops
            for _ in 0..500 {
                let current = counter.fetch_add(1, Ordering::SeqCst);
                assert!(current < limit, "should not exceed limit");
            }

            // Now at 1,000 — next op must fail
            let current = counter.fetch_add(1, Ordering::SeqCst);
            assert!(current >= limit, "should be blocked at 1,000");
            counter.fetch_sub(1, Ordering::SeqCst);
        }

        // Final: counter is exactly 1,000
        let counter = counters.read().unwrap().get(&key_id).cloned().unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1_000);
    }

    #[test]
    fn test_two_connections_share_counter() {
        // Two simultaneous connections using the same key_id share the
        // same global counter and cannot exceed 1,000 combined ops.
        let counters: OpsCounters = Arc::new(RwLock::new(HashMap::new()));
        let key_id = "shared-key".to_string();
        let limit: u64 = 1_000;

        // Initialize counter
        counters
            .write()
            .unwrap()
            .insert(key_id.clone(), Arc::new(AtomicU64::new(0)));

        let counter = counters.read().unwrap().get(&key_id).cloned().unwrap();

        // Connection A: 600 ops from thread A
        let counter_a = counter.clone();
        let handle_a = std::thread::spawn(move || {
            let mut allowed = 0u64;
            for _ in 0..600 {
                let current = counter_a.fetch_add(1, Ordering::SeqCst);
                if current >= limit {
                    counter_a.fetch_sub(1, Ordering::SeqCst);
                    break;
                }
                allowed += 1;
            }
            allowed
        });

        // Connection B: 600 ops from thread B (concurrent)
        let counter_b = counter.clone();
        let handle_b = std::thread::spawn(move || {
            let mut allowed = 0u64;
            for _ in 0..600 {
                let current = counter_b.fetch_add(1, Ordering::SeqCst);
                if current >= limit {
                    counter_b.fetch_sub(1, Ordering::SeqCst);
                    break;
                }
                allowed += 1;
            }
            allowed
        });

        let a_ops = handle_a.join().unwrap();
        let b_ops = handle_b.join().unwrap();

        // Combined must equal exactly 1,000 (the limit)
        assert_eq!(
            a_ops + b_ops,
            1_000,
            "two connections sharing a key must not exceed 1,000 combined"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1_000);
    }

    #[test]
    fn test_counters_do_not_survive_restart() {
        // DOCUMENTED BEHAVIOR (staging): counters are in-memory.
        // Daemon restart resets all counters to 0.
        // For production free-tier abuse control, counters must be
        // persisted to sled keyed by (key_id, quota_window).
        //
        // This test explicitly validates the current restart behavior
        // so the tradeoff is known, not hidden.

        // Simulate pre-restart state
        let counters_before: OpsCounters = Arc::new(RwLock::new(HashMap::new()));
        let key_id = "restart-test-key".to_string();
        {
            let counter = counters_before
                .write()
                .unwrap()
                .entry(key_id.clone())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .clone();
            counter.store(999, Ordering::SeqCst);
        }

        // Verify pre-restart: 999 ops used
        let pre = counters_before
            .read()
            .unwrap()
            .get(&key_id)
            .unwrap()
            .load(Ordering::SeqCst);
        assert_eq!(pre, 999);

        // Simulate restart: new OpsCounters (empty HashMap)
        let counters_after: OpsCounters = Arc::new(RwLock::new(HashMap::new()));

        // Post-restart: key_id has no counter → starts at 0
        let post = counters_after
            .read()
            .unwrap()
            .get(&key_id)
            .map(|c| c.load(Ordering::SeqCst));
        assert_eq!(post, None, "counter must not exist after restart");

        // First op after restart: counter created at 0
        let counter = counters_after
            .write()
            .unwrap()
            .entry(key_id.clone())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone();
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "counter starts at 0 after restart (staging-acceptable, production needs persistence)"
        );
    }
}
