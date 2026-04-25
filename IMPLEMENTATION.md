# Cachee Evidence Infrastructure — Implementation Plan

**CONFIDENTIAL — H33.ai, Inc.**
**Author:** Eric Beans, CEO
**Version:** 1.0 — April 23, 2026

This document specifies the exact implementation sequence for transforming Cachee
from a cache engine into a cryptographic evidence infrastructure. The type system
is defined (20 source files, 65 public types, clean compile). This document
specifies what gets wired, in what order, with what dependencies, and what the
acceptance criteria are for each piece.

The 4 locks (Phase 1) are non-negotiable. Nothing ships without them.

---

## PHASE 1: THE FOUR LOCKS

**Timeline:** 4-6 weeks
**Dependency:** None (foundational)
**Outcome:** Every write carries a computation identity. Every read returns a trust contract. Every entry has a lifecycle state. Verification cost is configurable.

If Phase 1 is wrong, everything downstream is wrong. These are the load-bearing walls.

---

### Lock 1: Computation Fingerprint Enforcement

**The invariant:** No value enters Cachee without a `ComputationFingerprint`. A value without a fingerprint is data. A value with a fingerprint is a reproducible computation artifact. Cachee stores artifacts, not data.

**Files to modify:**
- `src/cache_api.rs` — `CacheeStore::cache_verified()` MUST reject entries with empty fingerprints
- `src/archive.rs` — `CacheeArchiveBundle::serialize()` already includes fingerprint (done)
- `cachee-core` (`engine.rs`) — the DashMap `set()` path must accept and store fingerprints
- `src/resp.rs` — RESP SET command extended: `SET key value FP <fingerprint_hex>`
- `src/daemon.rs` — daemon stores fingerprint alongside value in the shard

**Implementation detail:**

Step 1.1: Extend the DashMap value type
```
Current:  DashMap<String, (Vec<u8>, Instant)>  // value + expiry
Needed:   DashMap<String, CacheSlot>

struct CacheSlot {
    value: Vec<u8>,
    fingerprint: ComputationFingerprint,
    expires_at: Instant,
    state: EntryState,           // from lifecycle.rs
    trust: TrustLevel,           // from trust.rs
    temporal: TemporalBinding,   // from lifecycle.rs
    provenance: Provenance,      // from trust.rs
    created_at: u64,
}
```

This is the core change. Every value in the cache carries its full identity, lifecycle state, and trust metadata. The `CacheSlot` IS the storage model.

Step 1.2: Fingerprint computation helper
```
// Developer calls this before caching
let fp = ComputationFingerprint::new(
    &input_bytes,          // hashed automatically
    "h33-stark-verify",    // computation definition
    &stark_config_bytes,   // parameter set
    "cachee-core/0.2.0",   // engine version
    Some("secp256k1-air"), // circuit ID
    HardwareClass::Deterministic,
);
```

The `new()` constructor hashes the inputs automatically. The developer provides the raw bytes; the fingerprint computes SHA3-256 internally. This prevents fingerprint misuse (developer passing pre-hashed values incorrectly).

Step 1.3: Content address includes fingerprint
```
content_address = SHA3-256(primitive || content_hash || fingerprint.digest())
```

Already implemented in the type. Needs to be enforced in the storage layer — the DashMap key for content-addressed lookups uses this formula.

Step 1.4: RESP protocol extension
```
SET mykey myvalue FP <hex-encoded-fingerprint>
```

If `FP` is omitted, the daemon REJECTS the write in strict mode and WARNS in permissive mode. Configuration: `cachee init --strict` enables strict mode. Default: permissive (for backward compatibility during migration).

**Acceptance criteria:**
- [ ] A SET without a fingerprint in strict mode returns `-ERR computation fingerprint required`
- [ ] A SET with a fingerprint stores it in `CacheSlot.fingerprint`
- [ ] `content_address()` produces different addresses for same value with different fingerprints
- [ ] Two identical outputs from different computations produce different cache entries
- [ ] `cachee-verify` includes fingerprint in its verification output
- [ ] 12 unit tests covering: empty fingerprint rejection, fingerprint round-trip, content address determinism, different inputs same output, same input different params

**What breaks if this is wrong:** The entire "proof reuse" story collapses. A regulator asks "was this the same computation?" and you cannot answer. Cache poisoning becomes possible by substituting a valid-looking result from a different computation.

---

### Lock 2: Invalidation Lifecycle State Machine

**The invariant:** Every cache entry has an explicit lifecycle state. State transitions are attested. There is no implicit invalidation (no silent TTL expiry, no LRU eviction of truth claims).

**Files to modify:**
- `src/lifecycle.rs` — state machine implementation (types already defined)
- `src/cache_api.rs` — `invalidate()` and `supersede()` implementations
- `cachee-core` (`engine.rs`) — state stored in `CacheSlot.state`
- `src/daemon.rs` — lifecycle state exposed via RESP INFO command
- `src/resp.rs` — new commands: `INVALIDATE key REASON <reason>`, `SUPERSEDE oldkey newkey`

**Implementation detail:**

Step 2.1: State machine transitions
```
Active → Superseded(successor_address)    // new result replaces old
Active → Revoked(reason, attestation)     // invalid or compromised
Active → Expired                          // validity window closed
Active → Deprecated(family, date)         // crypto family downgraded

Superseded → (terminal, read-only)
Revoked → (terminal, read-only)
Expired → Active                          // re-validated
Deprecated → Active                       // re-attested with new family
```

Every transition except expiry produces an attestation record. The transition itself is a cacheable event with its own H33-74 primitive.

Step 2.2: State machine enforcement
```
fn transition(slot: &mut CacheSlot, new_state: EntryState) -> Result<TransitionAttestation> {
    // Validate transition is legal
    match (&slot.state, &new_state) {
        (Active, Superseded{..}) => Ok(()),
        (Active, Revoked{..}) => Ok(()),
        (Active, Expired) => Ok(()),
        (Active, Deprecated{..}) => Ok(()),
        (Expired, Active) => Ok(()),        // re-validation
        (Deprecated, Active) => Ok(()),     // re-attestation
        (Superseded, _) => Err("terminal state"),
        (Revoked, _) => Err("terminal state"),
        _ => Err("illegal transition"),
    }?;
    
    let attestation = attest_transition(&slot, &new_state);
    slot.state = new_state;
    Ok(attestation)
}
```

Step 2.3: Supersession chains
```
// When result A is superseded by result B:
// 1. A.state = Superseded { successor: B.content_address }
// 2. B stores a backlink: B.supersedes = Some(A.content_address)
// 3. Both are retained permanently
// 4. Read of A returns B with full chain history
```

The chain is stored as a linked list of content addresses. `read_verified("A")` follows the chain and returns B with the chain visible in the response.

Step 2.4: No silent eviction of attested entries
```
// CacheeLFU eviction SKIPS entries with state != Active
// Only Active entries are candidates for eviction
// Superseded/Revoked/Expired/Deprecated entries are retained
// until explicit archival export (Phase 2)
```

This is critical. An attested computation result cannot be silently evicted. It can only be explicitly transitioned through the state machine.

**Acceptance criteria:**
- [ ] Every state transition produces an attestation record
- [ ] Terminal states (Superseded, Revoked) cannot be transitioned further
- [ ] Expired entries can be re-validated to Active
- [ ] Deprecated entries can be re-attested to Active
- [ ] Supersession chains are traversable: read(A) returns B when A is superseded
- [ ] CacheeLFU eviction skips non-Active entries
- [ ] RESP commands: `INVALIDATE`, `SUPERSEDE`, `STATE key` (returns lifecycle state)
- [ ] 15 unit tests covering: all legal transitions, all illegal transitions, chain traversal, eviction skip, attestation on transition

**What breaks if this is wrong:** A regulator finds that a result they relied on was silently evicted. A superseded result is served as current. A revoked result is treated as valid. The evidence store becomes legally indefensible.

---

### Lock 3: Read-Path Trust Contract

**The invariant:** Every read from Cachee returns not just the value, but the full trust context: computation fingerprint, verification status, signature summary, provenance, lifecycle state, and validity window. This is what makes Cachee not Redis.

**Files to modify:**
- `src/read_contract.rs` — `CacheeReadResponse` construction
- `src/cache_api.rs` — `read_verified()` implementation
- `src/resp.rs` — RESP GET extended: `GET key` returns value, `GETVERIFIED key` returns full contract
- `src/daemon.rs` — daemon constructs `CacheeReadResponse` from `CacheSlot`

**Implementation detail:**

Step 3.1: Two read paths
```
// Standard Redis-compatible path (backward compatible)
GET key → value bytes only (same as Redis)

// Verified read path (the Cachee difference)
GETVERIFIED key → JSON-encoded CacheeReadResponse
{
    "value": "<base64>",
    "fingerprint": {
        "input_hash": "abc...",
        "computation_hash": "def...",
        "parameter_hash": "ghi...",
        "version": { "engine": "h33-stark", "version": "1.0.0" }
    },
    "verification": {
        "status": "cached_verification",
        "originally_verified_at": 1776000000,
        "age_secs": 3600
    },
    "signatures": {
        "mldsa_valid": true,
        "falcon_valid": true,
        "slhdsa_valid": true,
        "two_of_three": true
    },
    "provenance": {
        "computed_by": "node-abc",
        "computed_at": 1776000000,
        "computation_duration_us": 25
    },
    "state": "active",
    "validity": {
        "valid_from": 1776000000,
        "valid_until": 1776300000
    }
}
```

Step 3.2: Verification on read (cost model integration)
```
fn read_verified(&self, key: &str) -> Result<CacheeReadResponse> {
    let slot = self.get_slot(key)?;
    
    // Apply verification mode
    let verification = match slot.trust.verification_mode {
        AlwaysVerify => {
            let result = slot.verify_signatures();
            slot.trust.last_verified_at = now();
            VerificationStatus::FullyVerified { checked_at: now() }
        }
        TrustCached => {
            VerificationStatus::CachedVerification {
                originally_verified_at: slot.trust.last_verified_at,
                age_secs: now() - slot.trust.last_verified_at,
            }
        }
        Probabilistic { sample_rate } => {
            if random::<f64>() < sample_rate {
                slot.verify_signatures();
                VerificationStatus::FullyVerified { checked_at: now() }
            } else {
                VerificationStatus::Unverified {
                    last_verified_at: slot.trust.last_verified_at,
                    trust_score: slot.trust.trust_score,
                }
            }
        }
        AgeWeighted { max_age } => {
            if now() - slot.trust.last_verified_at > max_age {
                slot.verify_signatures();
                VerificationStatus::FullyVerified { checked_at: now() }
            } else {
                VerificationStatus::CachedVerification { .. }
            }
        }
    };
    
    // Follow supersession chain if entry is superseded
    if let Superseded { successor } = &slot.state {
        return self.read_verified_by_address(successor);
    }
    
    Ok(CacheeReadResponse {
        value: slot.value.clone(),
        fingerprint: slot.fingerprint.clone(),
        verification,
        signatures: slot.signature_summary(),
        provenance: slot.provenance.clone(),
        state: slot.state.clone(),
        validity: slot.temporal.validity.clone(),
    })
}
```

Step 3.3: Provenance tracking
Every write records who computed the result:
```
CacheSlot {
    provenance: Provenance {
        computed_by: node_id(),   // this node's identity
        computed_at: now_ns(),
        computation_duration_us: elapsed,
        verified_by: vec![],      // populated on first verification
    },
    ...
}
```

When a federated peer verifies the result independently, they add their node ID to `verified_by`. More independent verifiers = higher trust score.

**Acceptance criteria:**
- [ ] `GET key` returns raw value (Redis backward compatible)
- [ ] `GETVERIFIED key` returns full `CacheeReadResponse` as JSON
- [ ] Verification mode is applied on every verified read
- [ ] `AlwaysVerify` actually re-checks signatures (not a no-op)
- [ ] `Probabilistic` samples at the configured rate (test with 10K reads at 0.1 rate, expect ~1K verifications)
- [ ] Superseded entries automatically redirect to successor
- [ ] Expired entries return the value with `state: "expired"` (not a miss)
- [ ] Provenance is populated on every write
- [ ] 18 unit tests covering: both read paths, all 4 verification modes, supersession redirect, expired read, provenance population, trust score calculation

**What breaks if this is wrong:** Cachee returns values without context. An integrator caches a revoked result as valid. A regulator cannot determine when a result was last verified. The "not Redis" claim is empty.

---

### Lock 4: Verification Cost Model (Tenant Configuration)

**The invariant:** Each tenant (or deployment) configures how aggressively Cachee verifies results on read. The configuration is explicit, auditable, and itself attested.

**Files to modify:**
- `src/trust.rs` — `VerificationMode` enforcement
- `src/config.rs` — add tenant-level verification config
- `src/daemon.rs` — load verification config on startup
- `src/plan.rs` — show verification mode in `cachee usage`

**Implementation detail:**

Step 4.1: Configuration
```
# ~/.cachee/config.toml

[verification]
mode = "age_weighted"        # always_verify | trust_cached | probabilistic | age_weighted
sample_rate = 0.01           # for probabilistic mode (1% of reads)
max_age_secs = 3600          # for age_weighted mode (re-verify after 1 hour)

[verification.overrides]
# Per computation-type overrides
"PostQuantumMigration" = "always_verify"
"BiometricAuth" = "always_verify"
"DocumentAttest" = "probabilistic"
```

Step 4.2: Override hierarchy
```
1. Per-entry override (set at write time via CachePolicy)
2. Per-computation-type override (config.toml)
3. Global default (config.toml)
```

The most specific wins. A regulator can mandate `always_verify` for a specific computation type even if the global default is `trust_cached`.

Step 4.3: Verification audit log
Every verification event (whether triggered or skipped) is logged:
```
struct VerificationEvent {
    key: String,
    mode: VerificationMode,
    triggered: bool,
    result: Option<VerificationResult>,
    timestamp: u64,
}
```

This log is queryable. A regulator can ask: "How many verifications were performed on this computation type in the last 30 days?" and get an exact answer.

**Acceptance criteria:**
- [ ] Config loads from `config.toml` on startup
- [ ] Per-computation-type overrides work
- [ ] Per-entry overrides (set at write time) take precedence
- [ ] Verification events are logged with timestamp
- [ ] `cachee usage` shows current verification mode and stats
- [ ] Config changes are themselves attested (the change event gets an H33-74 primitive)
- [ ] 10 unit tests covering: config loading, override hierarchy, verification event logging, mode switching

**What breaks if this is wrong:** An enterprise customer cannot prove to their auditor what verification policy was in effect during a specific period. A regulator mandates `always_verify` but the system silently falls back to `trust_cached` under load. The trust model has no teeth.

---

## PHASE 2: STORAGE + EXPORT

**Timeline:** 3-4 weeks (starts after Phase 1 locks are verified)
**Dependency:** Phase 1 complete (CacheSlot with fingerprint, lifecycle, trust)
**Outcome:** CAB files are real, exportable, independently verifiable artifacts.

---

### 2.1: Content-Addressed Filesystem Store

**The requirement:** Bundles stored and retrievable by `SHA3-256(primitive || content_hash || fingerprint.digest())`. Any party with the primitive can derive the retrieval key independently.

**Files to create:**
- `src/content_store.rs` — content-addressed filesystem backend

**Implementation detail:**

```
~/.cachee/store/
  ab/cd/ef...  (first 3 bytes as directory sharding)
    abcdef1234...full_hash.cab  (CAB file)
```

Directory sharding prevents filesystem performance degradation at millions of files. The path is deterministic from the content address.

```
trait ContentStore {
    fn put(&self, bundle: &CacheeArchiveBundle) -> Result<[u8; 32]>;
    fn get(&self, address: &[u8; 32]) -> Result<Option<CacheeArchiveBundle>>;
    fn exists(&self, address: &[u8; 32]) -> bool;
    fn delete(&self, address: &[u8; 32], attestation: &H33Primitive) -> Result<()>;
    fn list(&self, prefix: &[u8]) -> Result<Vec<[u8; 32]>>;
    fn export(&self, address: &[u8; 32], destination: &Path) -> Result<()>;
}
```

`delete()` requires an attestation — you cannot delete a bundle without producing a cryptographic record that you did so. This is the immutability guarantee.

**Acceptance criteria:**
- [ ] `put()` writes a `.cab` file at the deterministic path
- [ ] `get()` retrieves it and deserializes correctly
- [ ] Two different bundles with different fingerprints produce different addresses
- [ ] `delete()` fails without an attestation parameter
- [ ] `delete()` with attestation removes the file but logs the deletion event
- [ ] 1 million bundles can be stored and retrieved without filesystem degradation
- [ ] 8 unit tests

---

### 2.2: `cachee export` Command

**The requirement:** Export CAB bundles to local filesystem or S3 in the canonical format. Once exported, the customer owns the archive. H33 going away does not invalidate it.

**Files to modify:**
- `src/main.rs` — add `Export` command variant
- Create `src/export.rs` — export logic

**Implementation detail:**

```
cachee export --all --dest /backups/cachee/
cachee export --since 2026-04-01 --dest s3://my-bucket/cachee-archive/
cachee export --computation-type PostQuantumMigration --dest ./pq-exports/
cachee export --key "session:*" --dest ./session-exports/
```

Each exported file is a complete, self-contained CAB bundle. The export itself is attested — the fact that an export happened at time T for entries matching filter F is recorded.

**Acceptance criteria:**
- [ ] `--all` exports every bundle in the content store
- [ ] `--since` filters by timestamp
- [ ] `--computation-type` filters by computation type
- [ ] `--dest` supports local path and S3 URI
- [ ] Exported files are valid CAB bundles that `cachee-verify` can validate
- [ ] Export event is attested
- [ ] 6 unit tests

---

### 2.3: `cachee-verify` Standalone Binary

**The requirement:** A separate binary, publishable to crates.io, that takes a `.cab` file and outputs pass/fail. No network calls. No Cachee dependency. No H33 dependency. Uses only NIST public specifications and the signer's public keys (included in the bundle).

**Files to create:**
- `src/bin/verify.rs` — standalone verification binary
- Add `[[bin]] name = "cachee-verify"` to Cargo.toml

**Implementation detail:**

```
cachee-verify bundle.cab

Cachee Archive Bundle Verification
===================================
  Bundle version   : CAB1
  Content address  : ab3f...
  Computation type : PostQuantumMigration (0x12)
  Computed at      : 2026-04-23T14:30:00Z
  
  Computation Fingerprint:
    Input hash       : 7a2b...
    Computation hash : 9c4d...
    Parameter hash   : e1f2...
    Engine           : h33-stark/1.0.0
    Circuit          : secp256k1-air
    Hardware class   : Deterministic
  
  Signature Verification:
    ML-DSA-65   : PASS ✓
    FALCON-512  : PASS ✓
    SLH-DSA     : PASS ✓
    2-of-3      : PASS ✓
  
  Content Hash:
    SHA3-256    : PASS ✓ (matches)
  
  Lifecycle State  : Active
  Validity         : 2026-04-23 to 2026-07-23
  
  RESULT: VALID
```

The critical requirement: this binary must NOT import `cachee-core`, must NOT make network calls, must NOT depend on any H33 service. It uses `pqcrypto-dilithium`, `pqcrypto-falcon`, `pqcrypto-sphincsplus` (or equivalent NIST-compliant implementations) directly. The verification is mathematically complete from the bundle contents alone.

**Acceptance criteria:**
- [ ] Binary compiles independently (no cachee-core dependency)
- [ ] Verifies all 3 PQ signature families
- [ ] Verifies content hash (SHA3-256)
- [ ] Verifies computation fingerprint is present and non-empty
- [ ] Outputs human-readable report
- [ ] Exit code 0 = valid, exit code 1 = invalid
- [ ] Machine-readable JSON output with `--json` flag
- [ ] Works offline with no network
- [ ] 10 unit tests with known-good and known-bad bundles

---

### 2.4: L1 → L2 → L3 → L4 Tier Routing

**The requirement:** Values move between storage tiers based on access frequency, age, and policy. Tier transitions are logged and attested.

**Files to modify:**
- `src/storage.rs` — tier routing implementation
- `cachee-core` (`engine.rs`) — promote/demote hooks

**Implementation detail:**

```
L1 (in-memory DashMap)     → 31ns reads, CacheeLFU eviction
    ↓ demote (age > l1_max_age OR memory pressure)
L2 (local RocksDB/sled)    → ~100µs reads, persistent
    ↓ demote (age > l2_max_age)
L3 (S3/Azure/GCS)          → ~50ms reads, cheap
    ↓ export (explicit or scheduled)
L4 (CAB archive bundles)   → independently verifiable, customer-owned
```

Promotion on access: a read from L2 promotes to L1 if the entry's access frequency exceeds the CacheeLFU admission threshold. A read from L3 promotes to L2. L4 is write-only (export) — no promotion from L4.

**Acceptance criteria:**
- [ ] Demotion from L1 to L2 triggered by age policy
- [ ] Demotion from L2 to L3 triggered by age policy
- [ ] Promotion from L2 to L1 on frequent access
- [ ] Tier transitions are logged in observability metrics
- [ ] `cachee status` shows entry count per tier
- [ ] Non-Active entries (Superseded, Revoked) are demoted to L2 immediately (never evicted from L1, demoted instead)
- [ ] 12 unit tests

---

## PHASE 3: FEDERATION + DELIVERY

**Timeline:** 4-6 weeks (starts after Phase 2)
**Dependency:** Phase 2 complete (content store, CAB export, verification binary)
**Outcome:** Cachee instances synchronize across trust boundaries. Witness delivery pushes bundles to recipients. Public verification endpoint serves status.

---

### 3.1: Trust Boundary Enforcement

Every federated peer connection specifies a `TrustBoundary`. Incoming bundles are accepted or rejected based on this policy.

```
fn accept_bundle(peer: &FederationPeer, bundle: &CacheeArchiveBundle, policy: &TrustBoundary) -> bool {
    match policy {
        SelfOnly => false,  // never accept from peers
        TrustedPeers { peer_ids } => peer_ids.contains(&peer.node_id),
        AnyVerifiable => bundle.verify().valid,  // accept if signatures check out
        TrustedIssuers { issuer_keys } => {
            issuer_keys.iter().any(|k| k == &bundle.signer_keys.mldsa65)
        }
    }
}
```

### 3.2: Peer Sync Protocol

Simple pull-based sync:
```
1. Peer A sends SyncRequest { since_timestamp, max_bundles }
2. Peer B responds with SyncResponse { bundles, next_cursor }
3. Peer A validates each bundle against its TrustBoundary
4. Accepted bundles are stored locally
5. Rejected bundles are logged (not silently dropped)
```

Conflict resolution applies when two peers have the same content address but different content (should be impossible with proper fingerprinting, but handle it):
```
fn resolve_conflict(local: &CacheeArchiveBundle, remote: &CacheeArchiveBundle) -> Resolution {
    if local.content_address() == remote.content_address() {
        // Same address, same content — no conflict
        return Resolution::Identical;
    }
    // Different address = different computation — both valid, store both
    Resolution::StoreBoth
}
```

### 3.3: Witness Delivery

HTTP POST to designated recipients at attestation creation time:
```
POST https://recipient.example.com/cachee/witness
Content-Type: application/octet-stream
X-Cachee-Content-Address: <hex>
X-Cachee-Computation-Type: PostQuantumMigration

<CAB bundle bytes>
```

Delivery is fire-and-forget with retry. Each delivery attempt is logged. Successful delivery is itself attested.

### 3.4: Public Verification Endpoint

Unauthenticated GET endpoint:
```
GET /verify/<content_address_hex>

Response:
{
    "status": "valid",           // valid | invalid | expired | revoked | unknown
    "computation_type": "PostQuantumMigration",
    "computed_at": "2026-04-23T14:30:00Z",
    "signatures": { "mldsa": true, "falcon": true, "slhdsa": true },
    "state": "active"
}
```

No API key. No account. Anyone can check. This is the lightweight portability path.

**Phase 3 acceptance criteria:**
- [ ] Peer sync with trust boundary enforcement
- [ ] Conflict logging (no silent drops)
- [ ] Witness delivery with retry and attestation
- [ ] Public verification endpoint (no auth)
- [ ] 20 unit tests across all federation components

---

## PHASE 4: REGULATOR KEYS + ZK QUERY

**Timeline:** 8-12 weeks (starts after Phase 3, overlaps with STARK circuit work in scif-backend)
**Dependency:** Phase 3 complete + STARK circuits from scif-backend
**Outcome:** Regulators can query encrypted data and get mathematically proven answers without seeing the data.

This is the breakthrough. This is the patent. This is what no one else has.

---

### 4.1: Key Generation

```
// Data owner generates a regulator key
let reg_key = RegulatorKey::generate(
    owner_keypair,
    QueryScope {
        allowed_queries: vec![
            QueryType::AmlExposureCheck,
            QueryType::ComplianceScore,
        ],
        tenant_id: "bank-xyz",
        expires_at: Some(one_year_from_now()),
        revocable: true,
    },
);

// Key issuance is itself attested
assert!(reg_key.attestation.is_some());
```

### 4.2: Query Execution

```
// Regulator submits a query using their scoped key
let result = cachee.zk_query(
    &regulator_key,
    QueryType::AmlExposureCheck,
    &encrypted_data_reference,
)?;

// Result is a ZK proof, not the data
assert!(result.proof.len() > 0);
assert!(result.answer == QueryAnswer::Pass);  // or Fail, Score, Threshold
assert!(result.attestation.is_some());        // query execution attested
```

### 4.3: Proof Storage

Every ZK query result is stored in Cachee as a CAB bundle:
- Computation type: `ZkQuery`
- Fingerprint: includes query type, regulator key ID, data reference
- Value: the proof bytes + answer
- Attestation: H33-74 primitive on the query execution

Auditor keys can retrieve these proof records:
```
let proofs = cachee.read_by_key_type(
    &auditor_key,
    KeyType::Auditor,
    "bank-xyz",
    since: last_audit_date,
)?;
// Returns proof metadata only — not the underlying data
```

### 4.4: Circuit Requirements (scif-backend)

The ZK circuits live in scif-backend, not in cachee-cli. Cachee calls them via an FFI bridge or gRPC.

For each `QueryType`, a STARK AIR circuit must exist:
```
AmlExposureCheck → src/zkp/stark/aml_air.rs
ComplianceScore  → src/zkp/stark/compliance_air.rs
TemperatureCompliance → src/zkp/stark/temperature_air.rs
CollateralAdequacy → src/zkp/stark/collateral_air.rs
```

Each circuit:
- Takes encrypted data as private input
- Takes the query threshold as public input
- Produces a STARK proof that the answer is correct
- Does NOT reveal the private input

**Phase 4 acceptance criteria:**
- [ ] Regulator key generation with scope enforcement
- [ ] Key issuance attested under H33-74
- [ ] Query execution produces a verifiable STARK proof
- [ ] Proof stored as CAB bundle in Cachee
- [ ] Auditor key retrieves proof metadata only
- [ ] Out-of-scope queries are rejected at the key level (not the circuit level)
- [ ] Key revocation invalidates all future queries
- [ ] 25 unit tests across key generation, query execution, proof verification, access control

---

## PHASE 5: OBSERVABILITY + PRODUCTION HARDENING

**Timeline:** 2-3 weeks (parallel with Phase 4)
**Dependency:** Phase 1-3 complete
**Outcome:** The killer metric is visible. Production is monitorable. Trust is auditable.

---

### 5.1: The Killer Metric

```
cachee metrics

  Computation Savings Report
  ==========================
  Period           : 2026-04-01 to 2026-04-23
  Total requests   : 847,291,033
  Cache hits       : 839,821,884
  
  Computation avoided : 99.12%    ← THIS IS THE NUMBER THAT SELLS
  
  Estimated compute saved : 23,494 CPU-hours
  Estimated cost saved    : $7,048
  
  Trust Distribution:
    Fully verified      : 8,469,201 (1.0%)
    Cached verification : 831,352,683 (98.1%)
    Probabilistic pass  : 7,469,149 (0.9%)
```

### 5.2: Prometheus Endpoint

`/metrics` endpoint exposes all `CacheeMetrics` fields in Prometheus format. Grafana dashboards for: computation savings, trust distribution, tier utilization, federation health, lifecycle state distribution.

---

## DEPENDENCY GRAPH

```
Phase 1 (THE FOUR LOCKS)
  ├── Lock 1: Computation Fingerprint
  ├── Lock 2: Invalidation Lifecycle
  ├── Lock 3: Read-Path Trust Contract (depends on 1, 2)
  └── Lock 4: Verification Cost Model (depends on 3)
      │
Phase 2 (STORAGE + EXPORT)
  ├── 2.1: Content-Addressed Store (depends on 1)
  ├── 2.2: cachee export (depends on 2.1)
  ├── 2.3: cachee-verify binary (depends on 1, 2.1)
  └── 2.4: Tier Routing (depends on 2, 2.1)
      │
Phase 3 (FEDERATION + DELIVERY)
  ├── 3.1: Trust Boundaries (depends on 2.1, Lock 3)
  ├── 3.2: Peer Sync (depends on 3.1)
  ├── 3.3: Witness Delivery (depends on 2.1)
  └── 3.4: Public Verify Endpoint (depends on 2.3)
      │
Phase 4 (REGULATOR KEYS)
  ├── 4.1: Key Generation (depends on Lock 1)
  ├── 4.2: Query Execution (depends on STARK circuits in scif-backend)
  ├── 4.3: Proof Storage (depends on 2.1, Lock 2)
  └── 4.4: Circuits (parallel, scif-backend)
      │
Phase 5 (OBSERVABILITY) — parallel with Phase 4
```

---

## TOTAL TEST COVERAGE

| Phase | Tests |
|-------|-------|
| Lock 1: Computation Fingerprint | 12 |
| Lock 2: Invalidation Lifecycle | 15 |
| Lock 3: Read-Path Trust Contract | 18 |
| Lock 4: Verification Cost Model | 10 |
| Phase 2: Storage + Export | 36 |
| Phase 3: Federation + Delivery | 20 |
| Phase 4: Regulator Keys | 25 |
| Phase 5: Observability | 8 |
| **Total** | **144 tests** |

---

## THE ONE QUESTION THAT DETERMINES SUCCESS

After Phase 1, ask this:

> "Can two identical outputs from different computations be distinguished in the cache?"

If the answer is yes, the computation fingerprint works.
If the answer is no, everything downstream is built on sand.

That is Lock 1. That is why it is first. That is why it is non-negotiable.
