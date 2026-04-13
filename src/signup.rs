//! `cachee signup`, `cachee verify`, `cachee whoami` — account lifecycle.
//!
//! Flow:
//!   1. `cachee signup --email user@example.com` → sends verification code
//!   2. `cachee verify --code 123456` → validates, stores API key
//!   3. `cachee start` → daemon uses stored key for metering
//!
//! Zero friction: `cachee start` works without signup (free tier, local-only).
//! Signup unlocks: usage tracking, plan upgrades, D-Cachee federation.

use crate::config;
use serde::{Deserialize, Serialize};

const API_BASE: &str = "https://cachee.ai/.netlify/functions";

#[derive(Serialize)]
struct SignupRequest {
    email: String,
}

#[derive(Deserialize)]
struct SignupResponse {
    message: String,
    email: String,
    verification_id: String,
    #[serde(default)]
    code: Option<String>, // Only in dev mode
}

#[derive(Serialize)]
struct VerifyRequest {
    email: String,
    code: String,
    verification_id: String,
}

#[derive(Deserialize)]
struct VerifyResponse {
    api_key: String,
    email: String,
    plan: String,
    ops_limit: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub api_key: String,
    pub email: String,
}

pub fn credentials_path() -> std::path::PathBuf {
    config::cachee_dir().join("credentials.toml")
}

pub fn load_credentials() -> Option<Credentials> {
    let path = credentials_path();
    if !path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    toml::from_str(&content).ok()
}

fn save_credentials(creds: &Credentials) -> anyhow::Result<()> {
    let path = credentials_path();
    let content = toml::to_string_pretty(creds)?;
    std::fs::write(&path, &content)?;
    // Restrict permissions on credentials file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub async fn signup(email: &str) -> anyhow::Result<()> {
    // Validate email format (basic)
    if !email.contains('@') || !email.contains('.') {
        anyhow::bail!("Invalid email address: {email}");
    }

    // Check if already signed up
    if let Some(creds) = load_credentials() {
        println!("Already signed in as {}", creds.email);
        println!("To switch accounts, delete {} and re-signup", credentials_path().display());
        return Ok(());
    }

    println!("Creating Cachee account for {email}...");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{API_BASE}/cachee-signup"))
        .json(&SignupRequest { email: email.to_string() })
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Signup failed ({}): {}", status, body);
    }

    let result: SignupResponse = resp.json().await?;

    println!();
    println!("  {}", result.message);
    println!("  Email: {}", result.email);

    // In dev mode, show the code directly
    if let Some(code) = result.code {
        println!();
        println!("  [dev mode] Verification code: {code}");
        println!("  Run: cachee verify --email {} --code {}", result.email, code);
    } else {
        println!();
        println!("  Check your email for the verification code.");
        println!("  Run: cachee verify --email {} --code <code>", result.email);
    }

    // Store email + verification_id for verify step
    let pending_path = config::cachee_dir().join("pending_signup.toml");
    std::fs::write(&pending_path, format!("email = \"{}\"\nverification_id = \"{}\"\n", result.email, result.verification_id))?;

    Ok(())
}

pub async fn verify(email: Option<&str>, code: &str) -> anyhow::Result<()> {
    // Get email + verification_id from arg or pending signup
    let pending_path = config::cachee_dir().join("pending_signup.toml");
    let pending_content = if pending_path.exists() {
        std::fs::read_to_string(&pending_path).unwrap_or_default()
    } else {
        String::new()
    };

    let email = if let Some(e) = email {
        e.to_string()
    } else {
        pending_content.lines()
            .find(|l| l.starts_with("email"))
            .and_then(|l| l.split('"').nth(1))
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No pending signup found. Run cachee signup --email <email> first"))?
    };

    let verification_id = pending_content.lines()
        .find(|l| l.starts_with("verification_id"))
        .and_then(|l| l.split('"').nth(1))
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("No verification_id found. Run cachee signup --email <email> first"))?;

    println!("Verifying {email}...");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{API_BASE}/cachee-verify"))
        .json(&VerifyRequest {
            email: email.clone(),
            code: code.to_string(),
            verification_id,
        })
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Verification failed ({}): {}", status, body);
    }

    let result: VerifyResponse = resp.json().await?;

    // Save credentials
    save_credentials(&Credentials {
        api_key: result.api_key.clone(),
        email: result.email.clone(),
    })?;

    // Clean up pending signup
    let pending_path = config::cachee_dir().join("pending_signup.toml");
    let _ = std::fs::remove_file(&pending_path);

    // Update config with plan info
    if let Ok(mut cfg) = config::load() {
        cfg.plan.tier = result.plan.clone();
        cfg.plan.ops_per_month = result.ops_limit;
        let config_path = config::cachee_dir().join("config.toml");
        let toml_str = toml::to_string_pretty(&cfg)?;
        std::fs::write(&config_path, &toml_str)?;
    }

    println!();
    println!("  Account verified.");
    println!();
    println!("  Email   : {}", result.email);
    println!("  API key : {}...{}", &result.api_key[..12], &result.api_key[result.api_key.len()-4..]);
    println!("  Plan    : {} ({} ops/month)", result.plan, result.ops_limit);
    println!();
    println!("  Credentials saved to {}", credentials_path().display());
    println!();
    println!("  You're ready. Start with: cachee start");

    Ok(())
}

pub async fn whoami() -> anyhow::Result<()> {
    match load_credentials() {
        Some(creds) => {
            let cfg = config::load().ok();

            println!("Cachee Account");
            println!();
            println!("  Email   : {}", creds.email);
            println!("  API key : {}...{}", &creds.api_key[..12], &creds.api_key[creds.api_key.len()-4..]);

            if let Some(cfg) = cfg {
                println!("  Plan    : {}", cfg.plan.tier);
                println!("  Limit   : {} ops/month", cfg.plan.ops_per_month);
            }

            println!();
            println!("  Usage: cachee usage");
            println!("  Plans: cachee plan list");
        }
        None => {
            println!("Not signed in.");
            println!();
            println!("  Cachee works without an account (free tier, local-only).");
            println!("  Sign up to unlock: usage tracking, plan upgrades, D-Cachee federation.");
            println!();
            println!("  Sign up: cachee signup --email you@example.com");
        }
    }

    Ok(())
}

pub async fn logout() -> anyhow::Result<()> {
    let path = credentials_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
        println!("Logged out. Credentials removed.");
    } else {
        println!("Not signed in.");
    }
    Ok(())
}
