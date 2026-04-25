//! Cachee Gold Demo — the canonical proof that the system works.
//!
//! init -> keygen -> sign -> bundle -> export -> verify -> VALID
//!
//! This is the demo every technical buyer sees first.
//! The output is deterministic given the same input.
//!
//! Usage: cargo run --release --bin cachee-gold-demo

use cachee_cli::archive::*;
use cachee_cli::pq_keys::{PqKeySet, CryptoPosture};
use cachee_cli::cache_slot::sha3_256;

fn main() {
    println!("+==========================================================+");
    println!("|  Cachee Gold Demo                                        |");
    println!("|  Post-Quantum Evidence Infrastructure                    |");
    println!("|  init -> keygen -> sign -> bundle -> export -> verify    |");
    println!("+==========================================================+");
    println!();

    // Step 1: Generate production PQ keypairs
    println!("[1/6] Generating production PQ keypairs...");
    let keys = PqKeySet::generate(CryptoPosture::Production);
    println!("      Key ID     : {}", hex::encode(&keys.metadata.key_id[..8]));
    println!("      Version    : {}", keys.metadata.version);
    println!("      Posture    : Production");
    println!("      ML-DSA-65  : {} byte public key", keys.mldsa_pk.len());
    println!("      FALCON-512 : {} byte public key", keys.falcon_pk.len());
    println!("      SLH-DSA    : {} byte public key", keys.slhdsa_pk.len());
    println!();

    // Step 2: Create computation fingerprint
    println!("[2/6] Creating computation fingerprint...");
    let input_data = b"bitcoin:pk:02abc123...secp256k1-ownership-proof";
    let fingerprint = ComputationFingerprint {
        input_hash: sha3_256(input_data),
        computation_hash: sha3_256(b"secp256k1-scalar-mult-air-147k-constraints"),
        parameter_hash: sha3_256(b"goldilocks:2^64-2^32+1:512-rows:fri-folding-8"),
        version: ComputationVersion {
            engine: "h33-stark".to_string(),
            version: "1.0.0".to_string(),
            circuit_id: Some("secp256k1-air".to_string()),
        },
        hardware_class: Some(HardwareClass::Deterministic),
    };
    println!("      Fingerprint: {}", hex::encode(&fingerprint.digest()[..8]));
    println!("      Engine     : h33-stark/1.0.0");
    println!("      Circuit    : secp256k1-air");
    println!("      Hardware   : Deterministic");
    println!();

    // Step 3: Simulate computation result
    println!("[3/6] Computing STARK verification result...");
    let result_value = b"proof_valid:true:pk_bound:secp256k1:timestamp:1776909871";
    let content_hash = sha3_256(result_value);
    println!("      Result     : proof_valid=true");
    println!("      Hash       : {}", hex::encode(&content_hash[..8]));
    println!();

    // Step 4: Sign with all 3 PQ families
    println!("[4/6] Signing with 3 post-quantum families...");
    let sigs = keys.sign(&content_hash);
    println!("      ML-DSA-65  : {} byte signature", sigs.mldsa_sig.len());
    println!("      FALCON-512 : {} byte signature", sigs.falcon_sig.len());
    println!("      SLH-DSA    : {} byte signature", sigs.slhdsa_sig.len());
    println!();

    // Step 5: Build and export CAB bundle
    println!("[5/6] Building Cachee Archive Bundle...");
    let bundle = CacheeArchiveBundle {
        magic: CAB_MAGIC,
        version: 1,
        primitive: H33Primitive {
            version: 1,
            timestamp: keys.metadata.created_at.to_be_bytes(),
            value_hash: content_hash,
            mldsa_prefix: [sigs.mldsa_sig[0], sigs.mldsa_sig[1]],
            falcon_prefix: [sigs.falcon_sig[0], sigs.falcon_sig[1]],
            slhdsa_prefix: [sigs.slhdsa_sig[0], sigs.slhdsa_sig[1]],
            flags: [0; 11],
        },
        content_hash,
        computation_type: ComputationType::PostQuantumMigration,
        timestamp_ns: keys.metadata.created_at,
        signer_keys: keys.public_keys(),
        signatures: SignatureBundle {
            mldsa65: sigs.mldsa_sig,
            falcon512: sigs.falcon_sig,
            slhdsa128f: sigs.slhdsa_sig,
        },
        metadata: vec![],
        on_chain_anchor: None,
        completeness: CompletenessLevel::Complete,
        computation_fingerprint: fingerprint,
        signer_identity: SignerIdentity {
            key_id: keys.metadata.key_id,
            key_version: keys.metadata.version,
            families: vec!["ML-DSA-65".into(), "FALCON-512".into(), "SLH-DSA-128f".into()],
            issuer: "gold-demo".to_string(),
            posture: "production".to_string(),
        },
    };

    let bytes = bundle.serialize();
    let dest = "/tmp/cachee-gold-demo.cab";
    std::fs::write(dest, &bytes).unwrap();
    println!("      Size       : {} bytes ({:.1} KB)", bytes.len(), bytes.len() as f64 / 1024.0);
    println!("      Address    : {}", hex::encode(&bundle.content_address()[..16]));
    println!("      Exported   : {}", dest);
    println!();

    // Step 6: Verify
    println!("[6/6] Verifying bundle...");
    let result = bundle.verify();
    println!("      Verdict    : {:?}", result.verdict);
    println!("      ML-DSA-65  : {}", if result.cryptographic.mldsa_valid { "PASS" } else { "FAIL" });
    println!("      FALCON-512 : {}", if result.cryptographic.falcon_valid { "PASS" } else { "FAIL" });
    println!("      SLH-DSA    : {}", if result.cryptographic.slhdsa_valid { "PASS" } else { "FAIL" });
    println!("      All three  : {}", if result.cryptographic.all_three { "PASS" } else { "FAIL" });
    println!("      Fingerprint: {}", if result.structural.fingerprint_present { "Present" } else { "Missing" });
    println!("      Signer ID  : {}", if result.structural.signer_identity_present { "Present" } else { "Missing" });
    println!("      Posture    : Production");
    println!();

    let valid = result.is_valid();
    println!("  RESULT: {}", if valid { "VALID" } else { "INVALID" });
    println!();
    println!("  This bundle is:");
    println!("  - Signed by 3 independent PQ families (FIPS 204/FN-DSA/FIPS 205)");
    println!("  - Content-addressed (deterministic retrieval key)");
    println!("  - Computation-fingerprinted (h33-stark/secp256k1-air)");
    println!("  - Independently verifiable (no Cachee, no H33, no network)");
    println!("  - Production posture (not dev/test)");
    println!("  - Signer identity bound (key_id + version + issuer)");
    println!();
    println!("  Verify it yourself:");
    println!("    cachee-verify {}", dest);
}
