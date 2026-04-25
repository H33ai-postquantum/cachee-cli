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
use crate::cache_slot::{CacheSlot, parse_fingerprint};
use crate::config;
use crate::content_store::ContentStore;
use crate::lifecycle::{EntryState, TransitionAuthority, TransitionProof};
use crate::read_contract::{CacheeReadResponse, SignatureSummary, VerificationStatus};
use crate::trust::{Provenance, VerificationMode};
use crate::lifecycle::ValidityWindow;
use cachee_core::{CacheeEngine, EngineConfig, L0Config};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Slot registry — maps cache keys to their CacheSlot metadata.
///
/// The CacheeEngine handles raw byte storage (L0/L1); this map holds the
/// computation fingerprint, lifecycle state, trust level, and provenance
/// that make Cachee a verifiable system rather than a dumb key-value store.
type SlotRegistry = Arc<RwLock<HashMap<String, CacheSlot>>>;

/// Start the RESP server with CacheeEngine backing.
pub async fn start(foreground: bool, config_path: Option<String>) -> anyhow::Result<()> {
    let cfg = config::load()?;

    let strict_mode = cfg.verification.strict_fingerprint;
    let safe_read_mode = cfg.verification.read_mode == "safe";
    let issuer_id = cfg.issuer_id.clone();

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
            .map_err(|e| anyhow::anyhow!("Failed to open content store: {}", e))?
    );

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
    let pq_keys: Option<Arc<crate::pq_keys::PqKeySet>> = if cfg.attest_enabled && crate::pq_keys::PqKeySet::exists(&keys_path) {
        match crate::pq_keys::PqKeySet::load(&keys_path) {
            Ok(keys) => {
                println!("  PQ keys   : loaded (ML-DSA-65 + FALCON-512 + SLH-DSA-128f)");
                Some(Arc::new(keys))
            }
            Err(e) => {
                eprintln!("[WARN] Failed to load PQ keys: {}. Attestation disabled.", e);
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
    println!("Cachee v{} — post-quantum caching service", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  RESP server : {addr}");
    println!("  Max keys    : {}", cfg.max_keys);
    println!("  L0 hot tier : {} ({} shards)", if cfg.l0_enabled { "enabled" } else { "disabled" }, cfg.l0_shards);
    println!("  L2 store    : {} ({} bundles)", store_path.display(), content_store.len());
    println!("  Attest      : {}", if cfg.attest_enabled { "enabled (3-family PQ)" } else { "disabled" });
    println!("  Verify mode : {verify_mode_str}");
    println!("  Strict FP   : {strict_mode}");
    println!("  Metrics     : http://127.0.0.1:{}/metrics", cfg.metrics_port);
    println!("  Issuer ID   : {}", issuer_id);
    println!("  Plan        : {} ({} ops/month)", cfg.plan.tier, cfg.plan.ops_per_month);
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

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

                let response = handle_resp(&engine, &slots, &content_store, strict_mode, safe_read_mode, &issuer_id, &pq_keys, &buf[..n]);
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// RESP parser — handles SET, GET, GETVERIFIED, DEL, PING, INFO,
/// INVALIDATE, SUPERSEDE, STATE.
fn handle_resp(
    engine: &CacheeEngine,
    slots: &SlotRegistry,
    content_store: &ContentStore,
    strict_mode: bool,
    safe_read_mode: bool,
    issuer_id: &str,
    pq_keys: &Option<Arc<crate::pq_keys::PqKeySet>>,
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
            engine.set(key, bytes::Bytes::from(value_str), None);
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

        // ── GETVERIFIED key — full trust envelope as JSON ──────
        "GETVERIFIED" if parts.len() >= 2 => {
            match get_verified(engine, slots, parts[1]) {
                Some(response) => {
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
                        Ok(_transition) => "+OK\r\n".to_string(),
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
                        Ok(_transition) => "+OK\r\n".to_string(),
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
    let (signer_keys, signatures, completeness, mldsa_prefix, falcon_prefix, slhdsa_prefix) = match pq_keys {
        Some(keys) => {
            let sigs = keys.sign(&content_hash);
            let mp = if sigs.mldsa_sig.len() >= 2 {
                [sigs.mldsa_sig[0], sigs.mldsa_sig[1]]
            } else { [0; 2] };
            let fp = if sigs.falcon_sig.len() >= 2 {
                [sigs.falcon_sig[0], sigs.falcon_sig[1]]
            } else { [0; 2] };
            let sp = if sigs.slhdsa_sig.len() >= 2 {
                [sigs.slhdsa_sig[0], sigs.slhdsa_sig[1]]
            } else { [0; 2] };

            (
                keys.public_keys(),
                SignatureBundle {
                    mldsa65: sigs.mldsa_sig,
                    falcon512: sigs.falcon_sig,
                    slhdsa128f: sigs.slhdsa_sig,
                },
                CompletenessLevel::Complete,
                mp, fp, sp,
            )
        }
        None => (
            SignerPublicKeys { mldsa65: vec![], falcon512: vec![], slhdsa128f: vec![] },
            SignatureBundle { mldsa65: vec![], falcon512: vec![], slhdsa128f: vec![] },
            CompletenessLevel::Partial,
            [0u8; 2], [0u8; 2], [0u8; 2],
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
/// Returns `None` if the key does not exist in either the engine or the
/// slot registry. If the entry exists in the engine but not the slot
/// registry (e.g. it was SET before this daemon started), a minimal
/// response with empty fingerprint is returned.
fn get_verified(
    engine: &CacheeEngine,
    slots: &SlotRegistry,
    key: &str,
) -> Option<CacheeReadResponse> {
    // 1. Get raw value from engine
    let (value, _level) = engine.get(key)?;

    // 2. Get CacheSlot metadata (or construct minimal default)
    let registry = slots.read().unwrap();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    match registry.get(key) {
        Some(slot) => {
            let verification = VerificationStatus::CachedVerification {
                originally_verified_at: slot.trust.last_verified_at,
                age_secs: now_ns.saturating_sub(slot.trust.last_verified_at) / 1_000_000_000,
            };

            Some(CacheeReadResponse {
                value: value.to_vec(),
                fingerprint: slot.fingerprint.clone(),
                verification,
                signatures: SignatureSummary {
                    mldsa_valid: None,
                    falcon_valid: None,
                    slhdsa_valid: None,
                    two_of_three: false,
                    last_full_check: 0,
                },
                provenance: slot.provenance.clone(),
                state: slot.state.clone(),
                validity: slot.temporal.validity.clone(),
            })
        }
        None => {
            // Key exists in engine but not in slot registry (pre-Phase-1 data)
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
