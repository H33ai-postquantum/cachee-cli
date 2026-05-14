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
    println!(
        "  PQ attestation: {}",
        if cfg.attest_enabled {
            "included"
        } else {
            "available on upgrade"
        }
    );
    println!();
    println!("  Upgrade: cachee plan upgrade <tier>");
    println!("  Plans:   cachee plan list");

    Ok(())
}

pub async fn list() -> anyhow::Result<()> {
    println!("Cachee Plans");
    println!();
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "Tier", "Ops/month", "Rate/1M", "Price/month", "Features"
    );
    println!("  {}", "-".repeat(80));
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "free", "1M (trial)", "—", "$0", "L0+L1, CacheeLFU"
    );
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "payg", "Usage-based", "$15", "Usage", "Full analytics"
    );
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "starter", "20M", "$9.95", "$199", "+ PQ attest"
    );
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "scale", "200M", "$5.00", "$999", "+ Sidecar, 5 regions"
    );
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "institutional", "10B", "$1.00", "$9,999", "+ Dedicated AM, SLA"
    );
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "institutional-plus", "50B", "$0.50", "$24,999", "+ Dedicated infra"
    );
    println!(
        "  {:<20} {:<14} {:<12} {:<14} {:<18}",
        "unlimited", "No cap", "—", "$99,999", "10TB mem, custom SLA"
    );
    println!();
    println!("  Unlimited: $99,999/mo includes 10TB memory. $5,000/TB/mo beyond.");
    println!("  PQ attestation included on Starter and above.");
    println!();
    println!("  Upgrade: cachee plan upgrade starter");

    Ok(())
}

pub async fn upgrade(tier: &str) -> anyhow::Result<()> {
    let valid = [
        "payg",
        "starter",
        "scale",
        "institutional",
        "institutional-plus",
        "unlimited",
    ];
    if !valid.contains(&tier) {
        anyhow::bail!("Unknown tier '{}'. Valid: {}", tier, valid.join(", "));
    }

    let creds = signup::load_credentials();
    if creds.is_none() {
        println!("Not signed in. Run: cachee signup --email you@example.com");
        return Ok(());
    }
    let creds = creds.unwrap();

    println!("Upgrading to: {tier}");
    println!();

    // Step 1: Request checkout URL from Auth1 (via Netlify proxy)
    let client = reqwest::Client::new();
    let resp = client
        .post("https://cachee.ai/api/cachee-plan")
        .json(&serde_json::json!({
            "api_key": creds.api_key,
            "action": "upgrade",
            "tier": tier,
        }))
        .send()
        .await;

    let checkout_url = match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            body["checkout_url"].as_str().map(|s| s.to_string())
        }
        Ok(r) => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let err = body["error"].as_str().unwrap_or("Unknown error");
            anyhow::bail!("Upgrade failed: {}", err);
        }
        Err(e) => {
            anyhow::bail!("Could not reach cachee.ai: {}", e);
        }
    };

    let Some(url) = checkout_url else {
        anyhow::bail!("No checkout URL returned. Contact support@cachee.ai");
    };

    // Step 2: Open checkout in browser
    println!("  Complete your upgrade:");
    println!("  {url}");
    println!();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(&url).spawn();
    println!("  Waiting for payment confirmation...");
    println!("  (press Ctrl+C to cancel — plan will not change until payment completes)");
    println!();

    // Step 3: Poll for payment confirmation (up to 5 minutes)
    let poll_url = "https://cachee.ai/api/cachee-usage";
    let mut confirmed = false;

    for attempt in 1..=60 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        match client
            .get(poll_url)
            .query(&[("api_key", &creds.api_key)])
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                let current_plan = body["plan"].as_str().unwrap_or("free");

                if current_plan == tier {
                    confirmed = true;
                    let ops_limit = body["ops_limit"].as_u64().unwrap_or(0);
                    println!("  Payment confirmed!");
                    println!();

                    // Step 4: NOW update local config (only after payment verified)
                    let mut cfg = config::load()?;
                    cfg.plan.tier = tier.to_string();
                    cfg.plan.ops_per_month = ops_limit;
                    if tier != "free" && tier != "payg" {
                        cfg.attest_enabled = true;
                    }

                    let config_path = config::cachee_dir().join("config.toml");
                    let toml_str = toml::to_string_pretty(&cfg)?;
                    std::fs::write(&config_path, &toml_str)?;

                    println!("  Plan        : {tier}");
                    println!("  Ops/month   : {}", format_ops(ops_limit));
                    println!("  Attestation : enabled");
                    println!();
                    println!("  Restart daemon: cachee stop && cachee start");
                    break;
                }
            }
            _ => {}
        }

        if attempt % 6 == 0 {
            println!("  Still waiting... ({attempt}/60)");
        }
    }

    if !confirmed {
        println!("  Timed out waiting for payment.");
        println!("  If you completed payment, run: cachee plan sync");
        println!("  Plan was NOT changed locally.");
    }

    Ok(())
}

/// Sync plan from server — verifies current subscription and updates local config.
pub async fn sync() -> anyhow::Result<()> {
    let creds = signup::load_credentials();
    if creds.is_none() {
        println!("Not signed in. Run: cachee signup --email you@example.com");
        return Ok(());
    }
    let creds = creds.unwrap();

    println!("Syncing plan from server...");

    let client = reqwest::Client::new();
    match client
        .get("https://cachee.ai/api/cachee-usage")
        .query(&[("api_key", &creds.api_key)])
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let plan = body["plan"].as_str().unwrap_or("free");
            let ops_limit = body["ops_limit"].as_u64().unwrap_or(10_000_000);

            let mut cfg = config::load()?;
            cfg.plan.tier = plan.to_string();
            cfg.plan.ops_per_month = ops_limit;
            if plan != "free" && plan != "payg" {
                cfg.attest_enabled = true;
            }

            let config_path = config::cachee_dir().join("config.toml");
            let toml_str = toml::to_string_pretty(&cfg)?;
            std::fs::write(&config_path, &toml_str)?;

            println!(
                "  Plan synced: {plan} ({} ops/month)",
                format_ops(ops_limit)
            );
        }
        Ok(r) => {
            let status = r.status();
            anyhow::bail!("Server returned {status}");
        }
        Err(e) => {
            anyhow::bail!("Could not reach server: {e}");
        }
    }

    Ok(())
}

pub async fn usage() -> anyhow::Result<()> {
    let cfg = config::load()?;

    // Try to get live stats from daemon
    let addr = format!("127.0.0.1:{}", cfg.port);
    let (live_ops, memory_bytes, keys, hit_rate) = match tokio::net::TcpStream::connect(&addr).await
    {
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
            (
                get_val("total_ops:"),
                get_val("used_memory:"),
                get_val("total_keys:"),
                get_f64("hit_rate:"),
            )
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
            println!(
                "  Memory used    : {:.1} MB",
                memory_bytes as f64 / (1024.0 * 1024.0)
            );
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
            println!(
                "  Memory overage : {:.2} TB x $5,000 = ${:.0}/mo",
                overage_tb, overage_cost
            );
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
            let pct = if cfg.plan.ops_per_month > 0 {
                live_ops as f64 / cfg.plan.ops_per_month as f64 * 100.0
            } else {
                0.0
            };
            if pct > 80.0 {
                println!("  Approaching free tier limit.");
                println!("  Upgrade: cachee plan upgrade starter");
            } else {
                println!(
                    "  Free tier: {} remaining",
                    format_ops(cfg.plan.ops_per_month.saturating_sub(live_ops))
                );
            }
        }
        "payg" => {
            let cost = live_ops as f64 / 1_000_000.0 * 15.0;
            println!(
                "  Estimated bill : ${:.2} ({} x $15/1M)",
                cost,
                format_ops(live_ops)
            );
        }
        "unlimited" => {
            let base = 99_999.0;
            let mem_overage = if memory_tb > 10.0 {
                (memory_tb - 10.0) * 5000.0
            } else {
                0.0
            };
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
