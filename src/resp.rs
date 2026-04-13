//! Direct cache operations from the CLI: `cachee set`, `cachee get`, `cachee del`

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::config;

async fn connect() -> anyhow::Result<TcpStream> {
    let cfg = config::load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);
    let stream = TcpStream::connect(&addr).await
        .map_err(|_| anyhow::anyhow!("Cannot connect to Cachee on {addr}. Is it running? Try `cachee start`"))?;
    Ok(stream)
}

pub async fn set(key: &str, value: &str, ttl: Option<u32>) -> anyhow::Result<()> {
    let mut stream = connect().await?;
    let cmd = if let Some(t) = ttl {
        format!("SET {key} {value} EX {t}\r\n")
    } else {
        format!("SET {key} {value}\r\n")
    };
    stream.write_all(cmd.as_bytes()).await?;

    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.contains("OK") {
        println!("OK");
    } else {
        println!("{}", response.trim());
    }

    Ok(())
}

pub async fn get(key: &str, show_receipt: bool) -> anyhow::Result<()> {
    let mut stream = connect().await?;
    let cmd = format!("GET {key}\r\n");
    stream.write_all(cmd.as_bytes()).await?;

    let mut buf = vec![0u8; 65536];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.starts_with("$-1") {
        println!("(nil)");
    } else if response.starts_with('$') {
        // Parse RESP bulk string
        if let Some(payload) = response.split("\r\n").nth(1) {
            println!("{payload}");
            if show_receipt {
                println!("\n  [attestation receipt would be shown here when attest is enabled]");
            }
        }
    } else {
        println!("{}", response.trim());
    }

    Ok(())
}

pub async fn del(key: &str) -> anyhow::Result<()> {
    let mut stream = connect().await?;
    let cmd = format!("DEL {key}\r\n");
    stream.write_all(cmd.as_bytes()).await?;

    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if response.contains(":1") {
        println!("(integer) 1");
    } else {
        println!("(integer) 0");
    }

    Ok(())
}
