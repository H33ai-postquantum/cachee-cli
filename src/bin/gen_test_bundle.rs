//! Generate a real CAB bundle with real PQ signatures for testing.
//! Usage: cargo run --bin gen-test-bundle -- /tmp/test.cab

use cachee_cli::archive::*;
use cachee_cli::crypto;
use cachee_cli::cache_slot::sha3_256;

fn main() {
    let dest = std::env::args().nth(1).unwrap_or_else(|| "/tmp/test_bundle.cab".to_string());

    let content = b"real computation result from STARK verification pipeline";
    let content_hash = sha3_256(content);

    // Generate REAL PQ signatures (ML-DSA-65 + FALCON-512 + SLH-DSA-128f)
    let keys = crypto::generate_test_bundle(&content_hash);

    let fingerprint = ComputationFingerprint {
        input_hash: sha3_256(b"transaction:0xabc123"),
        computation_hash: sha3_256(b"stark-verify-secp256k1"),
        parameter_hash: sha3_256(b"goldilocks:2^64-2^32+1"),
        version: ComputationVersion {
            engine: "h33-stark".to_string(),
            version: "1.0.0".to_string(),
            circuit_id: Some("secp256k1-air".to_string()),
        },
        hardware_class: Some(HardwareClass::Deterministic),
    };

    let bundle = CacheeArchiveBundle {
        magic: CAB_MAGIC,
        version: 1,
        primitive: H33Primitive {
            version: 1,
            timestamp: [0; 8],
            value_hash: content_hash,
            mldsa_prefix: [keys.mldsa_sig[0], keys.mldsa_sig[1]],
            falcon_prefix: [keys.falcon_sig[0], keys.falcon_sig[1]],
            slhdsa_prefix: [keys.slhdsa_sig[0], keys.slhdsa_sig[1]],
            flags: [0; 11],
        },
        content_hash,
        computation_type: ComputationType::PostQuantumMigration,
        timestamp_ns: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
        signer_keys: SignerPublicKeys {
            mldsa65: keys.mldsa_pk,
            falcon512: keys.falcon_pk,
            slhdsa128f: keys.slhdsa_pk,
        },
        signatures: SignatureBundle {
            mldsa65: keys.mldsa_sig,
            falcon512: keys.falcon_sig,
            slhdsa128f: keys.slhdsa_sig,
        },
        metadata: vec![],
        on_chain_anchor: None,
        completeness: CompletenessLevel::Complete,
        computation_fingerprint: fingerprint,
        signer_identity: SignerIdentity::default(),
    };

    let bytes = bundle.serialize();
    std::fs::write(&dest, &bytes).unwrap();

    println!("Generated CAB bundle: {}", dest);
    println!("  Size: {} bytes ({:.1} KB)", bytes.len(), bytes.len() as f64 / 1024.0);
    println!("  Content address: {}", hex::encode(&bundle.content_address()[..16]));
    println!("  Computation: PostQuantumMigration (0x12)");
    println!("  Engine: h33-stark/1.0.0 (secp256k1-air)");
    println!("  Signatures: ML-DSA-65 + FALCON-512 + SLH-DSA-128f");
}
