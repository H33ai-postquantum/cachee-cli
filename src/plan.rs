//! `cachee plan` / `cachee usage` — pricing, billing, metering.
//!
//! When signed in: talks to cachee.ai API for real usage data.
//! When not signed in: shows local config only.

use crate::config;
use crate::signup;

pub async fn show() -> anyhow::Result<()> {
    let cfg = config::load()?;

    println!("Cachee Plan");
    println!();
    println!("  Current tier  : {}", cfg.plan.tier);
    println!("  Ops/month     : {}", format_ops(cfg.plan.ops_per_month));
    println!("  Rate per op   : {}", format_rate(cfg.plan.rate_per_op));
    println!("  Max keys      : {}", cfg.max_keys);
    println!("  PQ attestation: {}", if cfg.attest_enabled { "included" } else { "available on upgrade" });
    println!();
    println!("  Upgrade: cachee plan upgrade <tier>");
    println!("  Plans:   cachee plan list");

    Ok(())
}

pub async fn list() -> anyhow::Result<()> {
    println!("Cachee Plans");
    println!();
    println!("  {:<16} {:<16} {:<14} {:<14} {:<12}", "Tier", "Ops/month", "Rate/op", "Price/month", "Features");
    println!("  {}", "-".repeat(75));
    println!("  {:<16} {:<16} {:<14} {:<14} {:<12}", "free",          "10M",   "—",          "$0",        "L0+L1, CacheeLFU");
    println!("  {:<16} {:<16} {:<14} {:<14} {:<12}", "starter",       "100M",  "$0.000005",  "$50",       "+ PQ attest");
    println!("  {:<16} {:<16} {:<14} {:<14} {:<12}", "professional",  "1B",    "$0.000005",  "$499",      "+ TLS, auth keys");
    println!("  {:<16} {:<16} {:<14} {:<14} {:<12}", "enterprise",    "10B+",  "$0.000005",  "$2,499",    "+ D-Cachee, SLA");
    println!();
    println!("  All paid plans: $0.000005 per op (5e-6). Flat rate, any volume.");
    println!("  PQ attestation included on all paid plans.");
    println!("  On-chain anchoring (Bitcoin/Solana/Ethereum) billed at chain gas cost.");
    println!();
    println!("  Upgrade: cachee plan upgrade starter");

    Ok(())
}

pub async fn upgrade(tier: &str) -> anyhow::Result<()> {
    let valid = ["starter", "professional", "enterprise"];
    if !valid.contains(&tier) {
        anyhow::bail!("Unknown tier '{}'. Valid tiers: {}", tier, valid.join(", "));
    }

    let mut cfg = config::load()?;
    let (ops, rate, price) = match tier {
        "starter" => (100_000_000u64, 0.000005, "$50/month"),
        "professional" => (1_000_000_000, 0.000005, "$499/month"),
        "enterprise" => (10_000_000_000, 0.000005, "$2,499/month"),
        _ => unreachable!(),
    };

    cfg.plan.tier = tier.to_string();
    cfg.plan.ops_per_month = ops;
    cfg.plan.rate_per_op = rate;

    // Enable attestation on paid plans
    if tier != "free" {
        cfg.attest_enabled = true;
    }

    let config_path = config::cachee_dir().join("config.toml");
    let toml_str = toml::to_string_pretty(&cfg)?;
    std::fs::write(&config_path, &toml_str)?;

    // If signed in, call the API to get a Stripe checkout URL
    if let Some(creds) = signup::load_credentials() {
        println!("Upgrading to: {tier}");
        println!();

        let client = reqwest::Client::new();
        let resp = client
            .post("https://cachee.ai/.netlify/functions/cachee-plan")
            .json(&serde_json::json!({
                "api_key": creds.api_key,
                "action": "upgrade",
                "tier": tier,
            }))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                if let Ok(body) = r.json::<serde_json::Value>().await {
                    if let Some(url) = body["checkout_url"].as_str() {
                        println!("  Complete your upgrade:");
                        println!("  {url}");
                        println!();
                        // Try to open in browser
                        #[cfg(target_os = "macos")]
                        let _ = std::process::Command::new("open").arg(url).spawn();
                        #[cfg(target_os = "linux")]
                        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
                        println!("  (opening in browser...)");
                    }
                }
            }
            _ => {
                println!("  Could not reach cachee.ai — applying locally.");
            }
        }
    } else {
        println!("Upgraded locally to: {tier}");
        println!("  Sign up to sync: cachee signup --email you@example.com");
    }

    println!();
    println!("  Ops/month      : {}", format_ops(ops));
    println!("  Rate per op    : $0.000005");
    println!("  Price          : {price}");
    println!("  PQ attestation : enabled");
    println!();
    println!("  Restart daemon: cachee stop && cachee start");

    Ok(())
}

pub async fn usage() -> anyhow::Result<()> {
    let cfg = config::load()?;

    // Try to get live stats from daemon
    let addr = format!("127.0.0.1:{}", cfg.port);
    let live_ops = match tokio::net::TcpStream::connect(&addr).await {
        Ok(mut stream) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(b"INFO\r\n").await?;
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await?;
            let info = String::from_utf8_lossy(&buf[..n]);
            // Parse total_ops from INFO response
            info.lines()
                .find(|l| l.starts_with("total_ops:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0)
        }
        Err(_) => 0,
    };

    let pct_used = if cfg.plan.ops_per_month > 0 {
        live_ops as f64 / cfg.plan.ops_per_month as f64 * 100.0
    } else {
        0.0
    };

    let overage_ops = if live_ops > cfg.plan.ops_per_month {
        live_ops - cfg.plan.ops_per_month
    } else {
        0
    };
    let overage_cost = overage_ops as f64 * cfg.plan.rate_per_op;

    println!("Cachee Usage");
    println!();
    println!("  Plan           : {}", cfg.plan.tier);
    println!("  Ops this cycle : {}", format_ops(live_ops));
    println!("  Limit          : {}", format_ops(cfg.plan.ops_per_month));
    println!("  Used           : {:.2}%", pct_used);

    // Progress bar
    let bar_width = 40;
    let filled = (pct_used / 100.0 * bar_width as f64).min(bar_width as f64) as usize;
    let empty = bar_width - filled;
    println!("  [{}{}]", "#".repeat(filled), "-".repeat(empty));

    if overage_ops > 0 {
        println!();
        println!("  OVERAGE: {} ops at ${}/op = ${:.2}",
            format_ops(overage_ops), cfg.plan.rate_per_op, overage_cost);
    }

    let remaining = cfg.plan.ops_per_month.saturating_sub(live_ops);
    println!();
    println!("  Remaining      : {}", format_ops(remaining));
    println!("  Rate per op    : {}", format_rate(cfg.plan.rate_per_op));

    if cfg.plan.tier == "free" && pct_used > 80.0 {
        println!();
        println!("  Approaching limit. Upgrade: cachee plan upgrade starter");
    }

    Ok(())
}

fn format_ops(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}B", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        format!("{n}")
    }
}

fn format_rate(r: f64) -> String {
    if r == 0.0 {
        "free".to_string()
    } else {
        format!("${r}")
    }
}
