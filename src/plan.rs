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
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "Tier", "Ops/month", "Rate/1M", "Price/month", "Features");
    println!("  {}", "-".repeat(80));
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "free",                "1M (trial)", "—",     "$0",       "L0+L1, CacheeLFU");
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "payg",                "Usage-based", "$15",  "Usage",    "Full analytics");
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "starter",             "20M",    "$9.95",     "$199",     "+ PQ attest");
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "scale",               "200M",   "$5.00",     "$999",     "+ Sidecar, 5 regions");
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "institutional",       "10B",    "$1.00",     "$9,999",   "+ Dedicated AM, SLA");
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "institutional-plus",  "50B",    "$0.50",     "$24,999",  "+ Dedicated infra");
    println!("  {:<20} {:<14} {:<12} {:<14} {:<18}", "unlimited",           "No cap", "—",         "$99,999",  "10TB mem, custom SLA");
    println!();
    println!("  Unlimited: $99,999/mo includes 10TB memory. $5,000/TB/mo beyond.");
    println!("  PQ attestation included on Starter and above.");
    println!();
    println!("  Upgrade: cachee plan upgrade starter");

    Ok(())
}

pub async fn upgrade(tier: &str) -> anyhow::Result<()> {
    let valid = ["payg", "starter", "scale", "institutional", "institutional-plus", "unlimited"];
    if !valid.contains(&tier) {
        anyhow::bail!("Unknown tier '{}'. Valid: {}", tier, valid.join(", "));
    }

    let mut cfg = config::load()?;
    let (ops, rate, price) = match tier {
        "payg" => (0u64, 0.000015, "$15/1M (usage-based)"),
        "starter" => (20_000_000, 0.00000995, "$199/month"),
        "scale" => (200_000_000, 0.000005, "$999/month"),
        "institutional" => (10_000_000_000, 0.000001, "$9,999/month"),
        "institutional-plus" => (50_000_000_000, 0.0000005, "$24,999/month"),
        "unlimited" => (u64::MAX, 0.0, "$99,999/month"),
        _ => unreachable!(),
    };

    cfg.plan.tier = tier.to_string();
    cfg.plan.ops_per_month = ops;
    cfg.plan.rate_per_op = rate;

    // Memory cap and overage for unlimited
    if tier == "unlimited" {
        cfg.plan.memory_cap_tb = 10.0;
        cfg.plan.overage_per_tb = 5000.0;
    } else {
        cfg.plan.memory_cap_tb = 0.0;
        cfg.plan.overage_per_tb = 0.0;
    }

    // Enable attestation on paid plans
    if tier != "free" && tier != "payg" {
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
    let (live_ops, memory_bytes, keys, hit_rate) = match tokio::net::TcpStream::connect(&addr).await {
        Ok(mut stream) => {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(b"INFO\r\n").await?;
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await?;
            let info = String::from_utf8_lossy(&buf[..n]);
            let get_val = |key: &str| -> u64 {
                info.lines()
                    .find(|l| l.starts_with(key))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0)
            };
            let get_f64 = |key: &str| -> f64 {
                info.lines()
                    .find(|l| l.starts_with(key))
                    .and_then(|l| l.split(':').nth(1))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0.0)
            };
            (get_val("total_ops:"), get_val("used_memory:"), get_val("total_keys:"), get_f64("hit_rate:"))
        }
        Err(_) => (0, 0, 0, 0.0),
    };

    let memory_gb = memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    let memory_tb = memory_gb / 1024.0;

    println!("Cachee Usage");
    println!();
    println!("  Plan           : {}", cfg.plan.tier);

    // Ops section
    if cfg.plan.ops_per_month == u64::MAX {
        println!("  Ops this cycle : {} (no cap)", format_ops(live_ops));
    } else if cfg.plan.ops_per_month > 0 {
        let pct_used = live_ops as f64 / cfg.plan.ops_per_month as f64 * 100.0;
        println!("  Ops this cycle : {}", format_ops(live_ops));
        println!("  Ops limit      : {}", format_ops(cfg.plan.ops_per_month));
        println!("  Ops used       : {:.1}%", pct_used);

        let bar_width = 40;
        let filled = (pct_used / 100.0 * bar_width as f64).min(bar_width as f64) as usize;
        let empty = bar_width - filled;
        println!("  [{}{}]", "#".repeat(filled), "-".repeat(empty));

        if live_ops > cfg.plan.ops_per_month {
            let overage = live_ops - cfg.plan.ops_per_month;
            let cost = overage as f64 * cfg.plan.rate_per_op;
            println!("  Ops overage    : {} = ${:.2}", format_ops(overage), cost);
        }
    }

    // Memory section
    println!();
    if memory_bytes > 0 {
        if memory_gb >= 1.0 {
            println!("  Memory used    : {:.2} GB", memory_gb);
        } else {
            println!("  Memory used    : {:.1} MB", memory_bytes as f64 / (1024.0 * 1024.0));
        }
    } else {
        println!("  Memory used    : (daemon not running)");
    }

    if cfg.plan.tier == "unlimited" {
        let cap_tb: f64 = 10.0;
        let overage_rate = 5000.0; // $5,000/TB/mo
        println!("  Memory cap     : {:.0} TB included", cap_tb);
        if memory_tb > cap_tb {
            let overage_tb = memory_tb - cap_tb;
            let overage_cost = overage_tb * overage_rate;
            println!("  Memory overage : {:.2} TB x $5,000 = ${:.0}/mo", overage_tb, overage_cost);
        } else {
            println!("  Memory headroom: {:.2} TB remaining", cap_tb - memory_tb);
        }
    }

    // Keys and hit rate
    if keys > 0 {
        println!("  Cached keys    : {}", format_ops(keys));
    }
    if hit_rate > 0.0 {
        println!("  Hit rate       : {:.1}%", hit_rate);
    }

    // Billing summary
    println!();
    match cfg.plan.tier.as_str() {
        "free" => {
            let pct = if cfg.plan.ops_per_month > 0 { live_ops as f64 / cfg.plan.ops_per_month as f64 * 100.0 } else { 0.0 };
            if pct > 80.0 {
                println!("  Approaching free tier limit.");
                println!("  Upgrade: cachee plan upgrade starter");
            } else {
                println!("  Free tier: {} remaining", format_ops(cfg.plan.ops_per_month.saturating_sub(live_ops)));
            }
        }
        "payg" => {
            let cost = live_ops as f64 / 1_000_000.0 * 15.0;
            println!("  Estimated bill : ${:.2} ({} x $15/1M)", cost, format_ops(live_ops));
        }
        "unlimited" => {
            let base = 99_999.0;
            let mem_overage = if memory_tb > 10.0 { (memory_tb - 10.0) * 5000.0 } else { 0.0 };
            println!("  Base fee       : $99,999");
            if mem_overage > 0.0 {
                println!("  Memory overage : ${:.0}", mem_overage);
                println!("  Estimated bill : ${:.0}", base + mem_overage);
            } else {
                println!("  Estimated bill : $99,999 (no overage)");
            }
        }
        _ => {
            if cfg.plan.ops_per_month > 0 && live_ops > cfg.plan.ops_per_month {
                let overage = live_ops - cfg.plan.ops_per_month;
                let cost = overage as f64 * cfg.plan.rate_per_op;
                println!("  Overage cost   : ${:.2}", cost);
            }
        }
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
