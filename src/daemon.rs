//! `cachee start` / `cachee stop` / `cachee status` — daemon lifecycle.

use crate::config;
use cachee_core::{CacheeEngine, EngineConfig, L0Config};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start the RESP server with CacheeEngine backing.
pub async fn start(foreground: bool, config_path: Option<String>) -> anyhow::Result<()> {
    let cfg = config::load()?;

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

    // Write PID file
    let pid_path = config::cachee_dir().join("cachee.pid");
    std::fs::write(&pid_path, std::process::id().to_string())?;

    let addr = format!("127.0.0.1:{}", cfg.port);
    let listener = TcpListener::bind(&addr).await?;

    println!("Cachee v{} — post-quantum caching service", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  RESP server : {addr}");
    println!("  Max keys    : {}", cfg.max_keys);
    println!("  L0 hot tier : {} ({} shards)", if cfg.l0_enabled { "enabled" } else { "disabled" }, cfg.l0_shards);
    println!("  Attest      : {}", if cfg.attest_enabled { "enabled (3-family PQ)" } else { "disabled" });
    println!("  Metrics     : http://127.0.0.1:{}/metrics", cfg.metrics_port);
    println!("  Plan        : {} ({} ops/month)", cfg.plan.tier, cfg.plan.ops_per_month);
    println!("  PID         : {}", std::process::id());
    println!();
    println!("  Ready for connections.");

    // Accept loop
    loop {
        let (mut socket, peer) = listener.accept().await?;
        let engine = engine.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };

                let response = handle_resp(&engine, &buf[..n]);
                if socket.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// Minimal RESP parser — handles SET, GET, DEL, PING, INFO
fn handle_resp(engine: &CacheeEngine, data: &[u8]) -> String {
    let input = String::from_utf8_lossy(data);
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.is_empty() {
        return "-ERR empty command\r\n".to_string();
    }

    match parts[0].to_uppercase().as_str() {
        "PING" => "+PONG\r\n".to_string(),
        "SET" if parts.len() >= 3 => {
            let key = parts[1].to_string();
            let value = parts[2..].join(" ");
            engine.set(key, bytes::Bytes::from(value), None);
            "+OK\r\n".to_string()
        }
        "GET" if parts.len() >= 2 => {
            match engine.get(parts[1]) {
                Some((value, level)) => {
                    let s = String::from_utf8_lossy(&value);
                    format!("${}\r\n{}\r\n", s.len(), s)
                }
                None => "$-1\r\n".to_string(),
            }
        }
        "DEL" if parts.len() >= 2 => {
            let deleted = engine.delete(parts[1]);
            format!(":{}\r\n", if deleted { 1 } else { 0 })
        }
        "INFO" => {
            let stats = engine.stats();
            let info = format!(
                "# Cachee\r\nversion:{}\r\ntotal_ops:{}\r\nhit_rate:{:.4}\r\nhits_l0:{}\r\nhits_l1:{}\r\nmisses:{}\r\nkeys:{}\r\nmemory_bytes:{}\r\n",
                env!("CARGO_PKG_VERSION"),
                stats.total_ops,
                stats.hit_rate,
                stats.hits.l0,
                stats.hits.l1,
                stats.misses,
                stats.key_count,
                stats.memory_bytes,
            );
            format!("${}\r\n{}\r\n", info.len(), info)
        }
        _ => "-ERR unknown command\r\n".to_string(),
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
