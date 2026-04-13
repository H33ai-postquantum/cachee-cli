//! `cachee flush`, `cachee dump`, `cachee restore`, `cachee ttl`, `cachee keys`

use crate::config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn flush(skip_confirm: bool) -> anyhow::Result<()> {
    if !skip_confirm {
        println!("This will delete ALL cached entries. Are you sure?");
        println!("  Run with --yes to skip this prompt.");
        return Ok(());
    }

    let cfg = config::load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);
    let mut stream = tokio::net::TcpStream::connect(&addr).await
        .map_err(|_| anyhow::anyhow!("Cannot connect to Cachee. Is it running?"))?;

    stream.write_all(b"FLUSHALL\r\n").await?;
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.contains("OK") {
        println!("All entries flushed.");
    } else {
        println!("Flush response: {}", resp.trim());
    }

    Ok(())
}

pub async fn dump(output: &str) -> anyhow::Result<()> {
    // In production: serialize all cache entries to binary format
    let cfg = config::load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);

    match tokio::net::TcpStream::connect(&addr).await {
        Ok(mut stream) => {
            stream.write_all(b"INFO\r\n").await?;
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await?;
            let info = String::from_utf8_lossy(&buf[..n]);

            // Extract key count
            let keys: u64 = info.lines()
                .find(|l| l.starts_with("keys:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);

            // Write a snapshot header
            let snapshot = format!(
                "{{\"format\":\"cachee-dump-v1\",\"keys\":{},\"timestamp\":{}}}\n",
                keys, now_unix(),
            );
            std::fs::write(output, &snapshot)?;

            println!("Snapshot saved to {output}");
            println!("  Keys: {keys}");
            println!("  Format: cachee-dump-v1");
            println!();
            println!("  Full binary dump with entry data coming in v0.2");
        }
        Err(_) => {
            anyhow::bail!("Cannot connect to Cachee. Is it running?");
        }
    }

    Ok(())
}

pub async fn restore(input: &str) -> anyhow::Result<()> {
    if !std::path::Path::new(input).exists() {
        anyhow::bail!("Snapshot file not found: {input}");
    }

    let content = std::fs::read_to_string(input)?;
    println!("Restoring from {input}");
    println!("  {content}");
    println!("  Full binary restore coming in v0.2");

    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
