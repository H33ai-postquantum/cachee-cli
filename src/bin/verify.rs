#![allow(clippy::unnecessary_map_or, clippy::redundant_closure, dead_code)]
//! `cachee-verify` — standalone CAB bundle verification.
//!
//! Takes a `.cab` file as input. Outputs VALID or INVALID.
//! No network calls. No Cachee dependency. No H33 dependency.
//! Uses only NIST public specifications and the signer's public keys
//! (included in the bundle).
//!
//! Usage:
//!   cachee-verify bundle.cab
//!   cachee-verify bundle.cab --json
//!   cachee-verify --dir /path/to/exports/

use std::path::PathBuf;
use std::process;

use cachee_cli::archive::{CacheeArchiveBundle, CAB_MAGIC};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "--help" || args[1] == "-h" {
        eprintln!("cachee-verify — standalone CAB bundle verification");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  cachee-verify <file.cab>          Verify a single bundle");
        eprintln!("  cachee-verify <file.cab> --json    Output as JSON");
        eprintln!("  cachee-verify --dir <path>         Verify all .cab files in directory");
        eprintln!();
        eprintln!("No network calls. No Cachee account. No H33 dependency.");
        eprintln!("Verification uses only NIST public specifications (FIPS 203/204/205)");
        eprintln!("and the signer's public keys included in the bundle.");
        process::exit(if args.len() < 2 { 1 } else { 0 });
    }

    let json_mode = args.iter().any(|a| a == "--json");
    let dir_mode = args.iter().position(|a| a == "--dir");

    if let Some(idx) = dir_mode {
        let dir = args.get(idx + 1).unwrap_or_else(|| {
            eprintln!("Error: --dir requires a path argument");
            process::exit(1);
        });
        verify_directory(dir, json_mode);
    } else {
        let path = &args[1];
        if path.starts_with('-') {
            eprintln!("Error: unknown flag '{}'", path);
            process::exit(1);
        }
        let result = verify_file(path);
        print_result(&result, json_mode);
        process::exit(if result.valid { 0 } else { 1 });
    }
}

struct BundleVerification {
    file: String,
    valid: bool,
    magic_ok: bool,
    version: u16,
    computation_type: String,
    timestamp: u64,
    fingerprint_present: bool,
    mldsa_valid: bool,
    falcon_valid: bool,
    slhdsa_valid: bool,
    two_of_three: bool,
    content_hash_hex: String,
    content_address_hex: String,
    engine: String,
    engine_version: String,
    circuit_id: Option<String>,
    on_chain_anchored: bool,
    posture: String,
    error: Option<String>,
}

fn verify_file(path: &str) -> BundleVerification {
    let file_path = PathBuf::from(path);

    // Read file
    let bytes = match std::fs::read(&file_path) {
        Ok(b) => b,
        Err(e) => {
            return BundleVerification {
                file: path.to_string(),
                valid: false,
                magic_ok: false,
                version: 0,
                computation_type: String::new(),
                timestamp: 0,
                fingerprint_present: false,
                mldsa_valid: false,
                falcon_valid: false,
                slhdsa_valid: false,
                two_of_three: false,
                content_hash_hex: String::new(),
                content_address_hex: String::new(),
                engine: String::new(),
                engine_version: String::new(),
                circuit_id: None,
                on_chain_anchored: false,
                posture: String::new(),
                error: Some(format!("Failed to read file: {}", e)),
            };
        }
    };

    // Check magic
    let magic_ok = bytes.len() >= 4 && bytes[0..4] == CAB_MAGIC;

    // Deserialize
    let bundle = match CacheeArchiveBundle::deserialize(&bytes) {
        Ok(b) => b,
        Err(e) => {
            return BundleVerification {
                file: path.to_string(),
                valid: false,
                magic_ok,
                version: 0,
                computation_type: String::new(),
                timestamp: 0,
                fingerprint_present: false,
                mldsa_valid: false,
                falcon_valid: false,
                slhdsa_valid: false,
                two_of_three: false,
                content_hash_hex: String::new(),
                content_address_hex: String::new(),
                engine: String::new(),
                engine_version: String::new(),
                circuit_id: None,
                on_chain_anchored: false,
                posture: String::new(),
                error: Some(format!("Deserialization failed: {}", e)),
            };
        }
    };

    // Verify signatures (real PQ crypto)
    let result = bundle.verify();

    // Check fingerprint
    let fp = &bundle.computation_fingerprint;
    let fingerprint_present = fp.input_hash != [0u8; 32] && fp.computation_hash != [0u8; 32];

    BundleVerification {
        file: path.to_string(),
        valid: result.valid() || result.two_of_three(),
        magic_ok,
        version: bundle.version,
        computation_type: format!("{:?}", bundle.computation_type),
        timestamp: bundle.timestamp_ns,
        fingerprint_present,
        mldsa_valid: result.mldsa_valid(),
        falcon_valid: result.falcon_valid(),
        slhdsa_valid: result.slhdsa_valid(),
        two_of_three: result.two_of_three(),
        content_hash_hex: hex::encode(bundle.content_hash),
        content_address_hex: hex::encode(bundle.content_address()),
        engine: fp.version.engine.clone(),
        engine_version: fp.version.version.clone(),
        circuit_id: fp.version.circuit_id.clone(),
        on_chain_anchored: bundle.on_chain_anchor.is_some(),
        posture: bundle.signer_identity.posture.clone(),
        error: None,
    }
}

fn verify_directory(dir: &str, json_mode: bool) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Error reading directory '{}': {}", dir, e);
            process::exit(1);
        }
    };

    let mut total = 0u64;
    let mut valid = 0u64;
    let mut invalid = 0u64;
    let mut results = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "cab") {
            let result = verify_file(&path.to_string_lossy());
            if result.valid {
                valid += 1;
            } else {
                invalid += 1;
            }
            total += 1;
            if json_mode {
                results.push(result);
            } else {
                let status = if result.valid { "VALID" } else { "INVALID" };
                let sigs = format!(
                    "ML-DSA:{} FALCON:{} SLH-DSA:{}",
                    if result.mldsa_valid { "ok" } else { "FAIL" },
                    if result.falcon_valid { "ok" } else { "FAIL" },
                    if result.slhdsa_valid { "ok" } else { "FAIL" },
                );
                println!("  {} {} [{}]", status, result.file, sigs);
            }
        }
    }

    if json_mode {
        let json = serde_json::json!({
            "directory": dir,
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "results": results.iter().map(|r| result_to_json(r)).collect::<Vec<_>>(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
    } else {
        println!();
        println!(
            "  Total: {} | Valid: {} | Invalid: {}",
            total, valid, invalid
        );
    }

    process::exit(if invalid > 0 { 1 } else { 0 });
}

fn print_result(r: &BundleVerification, json_mode: bool) {
    if json_mode {
        let json = result_to_json(r);
        println!(
            "{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        );
        return;
    }

    println!();
    println!("Cachee Archive Bundle Verification");
    println!("===================================");
    println!("  File             : {}", r.file);
    println!(
        "  Magic            : {}",
        if r.magic_ok {
            "CAB1 (valid)"
        } else {
            "INVALID"
        }
    );
    println!("  Version          : {}", r.version);
    println!("  Computation type : {}", r.computation_type);
    println!("  Timestamp        : {}", r.timestamp);
    println!("  Content hash     : {}", &r.content_hash_hex[..16]);
    println!("  Content address  : {}", &r.content_address_hex[..16]);
    println!();
    println!("  Computation Fingerprint:");
    if r.fingerprint_present {
        println!("    Engine         : {}/{}", r.engine, r.engine_version);
        if let Some(ref circuit) = r.circuit_id {
            println!("    Circuit        : {}", circuit);
        }
        println!("    Present        : YES");
    } else {
        println!("    Present        : NO (structural only)");
    }
    println!();
    println!("  Signature Verification:");
    println!(
        "    ML-DSA-65      : {}",
        if r.mldsa_valid { "PASS" } else { "FAIL" }
    );
    println!(
        "    FALCON-512     : {}",
        if r.falcon_valid { "PASS" } else { "FAIL" }
    );
    println!(
        "    SLH-DSA-128f   : {}",
        if r.slhdsa_valid { "PASS" } else { "FAIL" }
    );
    println!(
        "    2-of-3         : {}",
        if r.two_of_three { "PASS" } else { "FAIL" }
    );
    println!();
    println!(
        "  On-chain anchor  : {}",
        if r.on_chain_anchored { "YES" } else { "NO" }
    );
    println!();

    // Crypto posture warnings
    if r.posture == "development" {
        println!("  WARNING: Development keys — NOT valid for production use");
        println!();
    } else if r.posture == "testing" {
        println!("  WARNING: Testing keys — NOT valid for federation");
        println!();
    } else if r.posture == "production" {
        println!("  Posture          : Production");
        println!();
    } else if r.posture.is_empty() || r.posture == "unknown" {
        println!("  Posture          : Unknown (pre-v0.2 bundle)");
        println!();
    }

    if let Some(ref err) = r.error {
        println!("  ERROR: {}", err);
        println!();
    }

    let result_str = if r.valid { "VALID" } else { "INVALID" };
    println!("  RESULT: {}", result_str);
    println!();
    println!("  Verified using NIST FIPS 203/204/205 public specifications.");
    println!("  No Cachee account. No network calls. No H33 dependency.");
}

fn result_to_json(r: &BundleVerification) -> serde_json::Value {
    serde_json::json!({
        "file": r.file,
        "valid": r.valid,
        "magic": r.magic_ok,
        "version": r.version,
        "computation_type": r.computation_type,
        "timestamp_ns": r.timestamp,
        "fingerprint_present": r.fingerprint_present,
        "engine": r.engine,
        "engine_version": r.engine_version,
        "circuit_id": r.circuit_id,
        "signatures": {
            "mldsa65": r.mldsa_valid,
            "falcon512": r.falcon_valid,
            "slhdsa128f": r.slhdsa_valid,
            "two_of_three": r.two_of_three,
        },
        "content_hash": r.content_hash_hex,
        "content_address": r.content_address_hex,
        "on_chain_anchored": r.on_chain_anchored,
        "posture": r.posture,
        "error": r.error,
    })
}
