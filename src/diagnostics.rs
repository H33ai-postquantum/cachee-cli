//! `cachee info`, `cachee doctor`, `cachee metrics`, `cachee logs`, `cachee export`, `cachee sdk`

use crate::config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn info() -> anyhow::Result<()> {
    let cfg = config::load().ok();

    println!("Cachee Info");
    println!();
    println!("  Version    : {}", env!("CARGO_PKG_VERSION"));
    println!("  Arch       : {}", std::env::consts::ARCH);
    println!(
        "  OS         : {} {}",
        std::env::consts::OS,
        std::env::consts::FAMILY
    );
    println!(
        "  CPUs       : {}",
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    );
    println!("  Config dir : {}", config::cachee_dir().display());

    if let Some(cfg) = cfg {
        println!();
        println!("  Engine Config");
        println!("  Port       : {}", cfg.port);
        println!("  Max keys   : {}", cfg.max_keys);
        println!("  Default TTL: {}s", cfg.default_ttl);
        println!("  L0 enabled : {}", cfg.l0_enabled);
        println!("  L0 shards  : {}", cfg.l0_shards);
        println!("  Attest     : {}", cfg.attest_enabled);
        println!(
            "  Plan       : {} ({} ops/month)",
            cfg.plan.tier, cfg.plan.ops_per_month
        );
    } else {
        println!();
        println!("  Not initialized. Run: cachee init");
    }

    println!();
    println!("  Algorithms : ML-DSA-65 (3,309 bytes)");
    println!("             : FALCON-512 (690 bytes)");
    println!("             : SLH-DSA (29,000 bytes)");
    println!("  Substrate  : 58 bytes canonical");
    println!("  On-chain   : 74 bytes (fits Bitcoin OP_RETURN)");
    println!("  Eviction   : CacheeLFU (frequency sketch admission)");
    println!("  Protocol   : RESP (Redis-compatible)");
    println!("  Homepage   : https://cachee.ai/pq-cache");
    println!("  Patent     : pending (H33 Substrate specification)");

    Ok(())
}

pub async fn doctor() -> anyhow::Result<()> {
    println!("Cachee Doctor");
    println!();

    let mut issues = 0;

    // Check config exists
    let config_path = config::cachee_dir().join("config.toml");
    if config_path.exists() {
        println!("  [OK] Config found at {}", config_path.display());
    } else {
        println!("  [!!] Config not found. Run: cachee init");
        issues += 1;
    }

    // Check PQ identity
    let identity_path = config::cachee_dir().join("keys").join("identity.toml");
    if identity_path.exists() {
        println!("  [OK] PQ identity present");
    } else {
        println!("  [!!] PQ identity missing. Run: cachee init");
        issues += 1;
    }

    // Check if port is available or daemon is running
    if let Ok(cfg) = config::load() {
        let addr = format!("127.0.0.1:{}", cfg.port);
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                stream.write_all(b"PING\r\n").await?;
                let mut buf = vec![0u8; 64];
                let n = stream.read(&mut buf).await?;
                let resp = String::from_utf8_lossy(&buf[..n]);
                if resp.contains("PONG") {
                    println!("  [OK] Daemon running on {addr}");
                } else {
                    println!("  [??] Port {addr} in use but not responding to PING");
                    issues += 1;
                }
            }
            Err(_) => {
                println!("  [--] Daemon not running on {addr} (start with: cachee start)");
            }
        }

        // Check PID file consistency
        let pid_path = config::cachee_dir().join("cachee.pid");
        if pid_path.exists() {
            let pid_str = std::fs::read_to_string(&pid_path).unwrap_or_default();
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                if alive {
                    println!("  [OK] PID file matches running process ({pid})");
                } else {
                    println!("  [!!] Stale PID file (process {pid} not running). Removing.");
                    let _ = std::fs::remove_file(&pid_path);
                    issues += 1;
                }
            }
        }

        // Check TLS
        let tls_dir = config::cachee_dir().join("tls");
        if tls_dir.join("cert.pem").exists() && tls_dir.join("key.pem").exists() {
            println!("  [OK] TLS certificates present");
        } else {
            println!("  [--] TLS not configured (optional: cachee tls enable)");
        }

        // Check plan
        if cfg.plan.tier == "free" {
            println!("  [--] Free plan (10M ops/month). Upgrade: cachee plan upgrade starter");
        } else {
            println!(
                "  [OK] Plan: {} ({} ops/month)",
                cfg.plan.tier, cfg.plan.ops_per_month
            );
        }
    }

    // Check PQ keypairs (real crypto keys, not just identity.toml)
    let keys_path = config::cachee_dir().join("keys");
    let has_mldsa = keys_path.join("mldsa65.key").exists();
    let has_falcon = keys_path.join("falcon512.key").exists();
    let has_slhdsa = keys_path.join("slhdsa128f.key").exists();
    if has_mldsa && has_falcon && has_slhdsa {
        println!("  [OK] PQ keys loaded (ML-DSA-65 + FALCON-512 + SLH-DSA)");
    } else {
        let missing: Vec<&str> = [
            (!has_mldsa, "ML-DSA-65"),
            (!has_falcon, "FALCON-512"),
            (!has_slhdsa, "SLH-DSA"),
        ]
        .iter()
        .filter(|(m, _)| *m)
        .map(|(_, n)| *n)
        .collect();
        println!(
            "  [!!] Missing PQ keys: {}. Run: cachee init",
            missing.join(", ")
        );
        issues += 1;
    }

    // Check audit chain integrity
    let audit_path = config::cachee_dir().join("audit_log");
    if audit_path.exists() {
        match crate::audit::AuditLog::open(&audit_path, "doctor") {
            Ok(log) => match log.verify_chain() {
                Ok((count, None)) => {
                    println!(
                        "  [OK] Audit chain intact ({} entries, head={})",
                        count,
                        hex::encode(&log.head()[..8])
                    );
                }
                Ok((count, Some(broken_at))) => {
                    println!(
                        "  [!!] Audit chain BROKEN at sequence {} ({} entries before break)",
                        broken_at, count
                    );
                    issues += 1;
                }
                Err(e) => {
                    println!("  [!!] Audit chain verify error: {}", e);
                    issues += 1;
                }
            },
            Err(e) => {
                println!("  [!!] Cannot open audit log: {}", e);
                issues += 1;
            }
        }
    } else {
        println!("  [--] No audit log (created on first cachee start)");
    }

    // Check credentials
    let creds_path = config::cachee_dir().join("credentials.toml");
    if creds_path.exists() {
        let content = std::fs::read_to_string(&creds_path).unwrap_or_default();
        let api_key = content
            .lines()
            .find(|l| l.starts_with("api_key"))
            .and_then(|l| l.split('"').nth(1))
            .unwrap_or("");
        if api_key.starts_with("ck_live_") && api_key.len() == 40 {
            println!("  [OK] API key configured ({}...)", &api_key[..16]);
        } else if !api_key.is_empty() {
            println!(
                "  [??] API key format unexpected: {}...",
                &api_key[..api_key.len().min(12)]
            );
        } else {
            println!("  [--] No API key. Run: cachee signup --email you@company.com");
        }
    } else {
        println!("  [--] Not signed up. Run: cachee signup --email you@company.com");
    }

    // Check Auth1 reachability
    let auth1_url = std::env::var("AUTH1_PROXY_BASE")
        .unwrap_or_else(|_| "https://auth-api.z101.ai".to_string());
    match reqwest::Client::new()
        .get(format!("{}/health", auth1_url))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            println!("  [OK] Auth1 reachable ({})", auth1_url);
        }
        Ok(resp) => {
            println!("  [??] Auth1 responded {} ({})", resp.status(), auth1_url);
        }
        Err(_) => {
            println!(
                "  [!!] Auth1 unreachable ({}). Usage reporting will fail.",
                auth1_url
            );
            issues += 1;
        }
    }

    // Check content store
    let store_path = config::cachee_dir().join("content_store");
    if store_path.exists() {
        match crate::content_store::ContentStore::open(&store_path) {
            Ok(store) => {
                println!("  [OK] Content store: {} bundles", store.len());
            }
            Err(e) => {
                println!("  [!!] Content store error: {}", e);
                issues += 1;
            }
        }
    } else {
        println!("  [--] No content store (created on first cachee start)");
    }

    // Binary info
    println!(
        "  [OK] Cachee v{} ({}-{})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    println!("  [OK] Data dir: {}", config::cachee_dir().display());

    println!();
    if issues == 0 {
        println!("  All checks passed. No issues found.");
    } else {
        println!("  {} issue(s) found. See above.", issues);
    }

    Ok(())
}

pub async fn metrics() -> anyhow::Result<()> {
    let cfg = config::load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|_| anyhow::anyhow!("Cannot connect to Cachee on {addr}. Is it running?"))?;

    stream.write_all(b"INFO\r\n").await?;
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    let info = String::from_utf8_lossy(&buf[..n]);

    println!("Cachee Metrics");
    println!();

    // Parse and pretty-print
    for line in info.lines() {
        if line.starts_with('#') || line.starts_with('$') || line.trim().is_empty() {
            continue;
        }
        if let Some((key, val)) = line.split_once(':') {
            let label = match key.trim() {
                "version" => "Version",
                "total_ops" => "Total ops",
                "hit_rate" => "Hit rate",
                "hits_l0" => "L0 hits",
                "hits_l1" => "L1 hits",
                "misses" => "Misses",
                "keys" => "Keys stored",
                "memory_bytes" => "Memory",
                _ => key.trim(),
            };

            let display_val = if key.trim() == "hit_rate" {
                if let Ok(rate) = val.trim().parse::<f64>() {
                    format!("{:.2}%", rate * 100.0)
                } else {
                    val.trim().to_string()
                }
            } else if key.trim() == "memory_bytes" {
                if let Ok(bytes) = val.trim().parse::<u64>() {
                    format_bytes(bytes)
                } else {
                    val.trim().to_string()
                }
            } else {
                val.trim().to_string()
            };

            println!("  {:<14} : {}", label, display_val);
        }
    }

    Ok(())
}

pub async fn logs(lines: usize, follow: bool) -> anyhow::Result<()> {
    let log_path = config::cachee_dir().join("cachee.log");
    if !log_path.exists() {
        println!("No log file at {}", log_path.display());
        println!("Start daemon with: cachee start");
        return Ok(());
    }

    let content = std::fs::read_to_string(&log_path)?;
    let all_lines: Vec<&str> = content.lines().collect();
    let start = all_lines.len().saturating_sub(lines);
    for line in &all_lines[start..] {
        println!("{line}");
    }

    if follow {
        println!(
            "(follow mode not yet implemented — use: tail -f {})",
            log_path.display()
        );
    }

    Ok(())
}

pub async fn export(output: Option<String>) -> anyhow::Result<()> {
    let cfg = config::load()?;
    let addr = format!("127.0.0.1:{}", cfg.port);

    let mut stream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|_| anyhow::anyhow!("Cannot connect to Cachee on {addr}. Is it running?"))?;

    stream.write_all(b"INFO\r\n").await?;
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    let info = String::from_utf8_lossy(&buf[..n]);

    // Build JSON from INFO response
    let mut map = serde_json::Map::new();
    map.insert(
        "version".to_string(),
        serde_json::Value::String(env!("CARGO_PKG_VERSION").to_string()),
    );
    map.insert(
        "plan".to_string(),
        serde_json::Value::String(cfg.plan.tier.clone()),
    );

    for line in info.lines() {
        if let Some((key, val)) = line.split_once(':') {
            let k = key.trim().to_string();
            if k.is_empty() || k.starts_with('#') || k.starts_with('$') {
                continue;
            }
            if let Ok(n) = val.trim().parse::<u64>() {
                map.insert(k, serde_json::Value::Number(n.into()));
            } else if let Ok(f) = val.trim().parse::<f64>() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    map.insert(k, serde_json::Value::Number(n));
                }
            } else {
                map.insert(k, serde_json::Value::String(val.trim().to_string()));
            }
        }
    }

    let json = serde_json::to_string_pretty(&serde_json::Value::Object(map))?;

    match output {
        Some(path) => {
            std::fs::write(&path, &json)?;
            println!("Exported to {path}");
        }
        None => println!("{json}"),
    }

    Ok(())
}

pub async fn sdk_init(lang: &str, output: &str) -> anyhow::Result<()> {
    let valid = ["rust", "python", "node", "go"];
    if !valid.contains(&lang) {
        anyhow::bail!(
            "Unsupported language '{}'. Supported: {}",
            lang,
            valid.join(", ")
        );
    }

    let dir = std::path::Path::new(output);
    std::fs::create_dir_all(dir)?;

    let (filename, content) = match lang {
        "rust" => (
            "cachee_client.rs",
            r#"//! Cachee Rust client — connects to local daemon via RESP.
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct CacheeClient {
    addr: String,
}

impl CacheeClient {
    pub fn new(addr: &str) -> Self {
        Self { addr: addr.to_string() }
    }

    pub fn connect() -> Self {
        Self::new("127.0.0.1:6380")
    }

    pub fn set(&self, key: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(&self.addr)?;
        write!(stream, "SET {key} {value}\r\n")?;
        let mut buf = [0u8; 256];
        stream.read(&mut buf)?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(&self.addr)?;
        write!(stream, "GET {key}\r\n")?;
        let mut buf = vec![0u8; 65536];
        let n = stream.read(&mut buf)?;
        let resp = String::from_utf8_lossy(&buf[..n]);
        if resp.starts_with("$-1") {
            Ok(None)
        } else {
            Ok(resp.split("\r\n").nth(1).map(|s| s.to_string()))
        }
    }

    pub fn del(&self, key: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(&self.addr)?;
        write!(stream, "DEL {key}\r\n")?;
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf[..n]).contains(":1"))
    }
}
"#,
        ),
        "python" => (
            "cachee_client.py",
            r#""""Cachee Python client — connects to local daemon via RESP."""
import socket

class CacheeClient:
    def __init__(self, host="127.0.0.1", port=6380):
        self.host = host
        self.port = port

    def _send(self, cmd: str) -> str:
        with socket.create_connection((self.host, self.port), timeout=5) as s:
            s.sendall(f"{cmd}\r\n".encode())
            return s.recv(65536).decode()

    def set(self, key: str, value: str, ttl: int = None) -> bool:
        cmd = f"SET {key} {value}"
        if ttl:
            cmd += f" EX {ttl}"
        return "OK" in self._send(cmd)

    def get(self, key: str) -> str | None:
        resp = self._send(f"GET {key}")
        if resp.startswith("$-1"):
            return None
        parts = resp.split("\r\n")
        return parts[1] if len(parts) > 1 else None

    def delete(self, key: str) -> bool:
        return ":1" in self._send(f"DEL {key}")

# Usage:
# client = CacheeClient()
# client.set("session:abc", "user123", ttl=3600)
# value = client.get("session:abc")
"#,
        ),
        "node" => (
            "cachee-client.js",
            r#"/**
 * Cachee Node.js client — connects to local daemon via RESP.
 */
const net = require('net');

class CacheeClient {
  constructor(host = '127.0.0.1', port = 6380) {
    this.host = host;
    this.port = port;
  }

  _send(cmd) {
    return new Promise((resolve, reject) => {
      const client = net.createConnection({ host: this.host, port: this.port }, () => {
        client.write(`${cmd}\r\n`);
      });
      let data = '';
      client.on('data', (chunk) => { data += chunk.toString(); });
      client.on('end', () => resolve(data));
      client.on('error', reject);
      setTimeout(() => { client.destroy(); resolve(data); }, 5000);
    });
  }

  async set(key, value, ttl) {
    let cmd = `SET ${key} ${value}`;
    if (ttl) cmd += ` EX ${ttl}`;
    const resp = await this._send(cmd);
    return resp.includes('OK');
  }

  async get(key) {
    const resp = await this._send(`GET ${key}`);
    if (resp.startsWith('$-1')) return null;
    const parts = resp.split('\r\n');
    return parts[1] || null;
  }

  async del(key) {
    const resp = await this._send(`DEL ${key}`);
    return resp.includes(':1');
  }
}

module.exports = { CacheeClient };

// Usage:
// const { CacheeClient } = require('./cachee-client');
// const client = new CacheeClient();
// await client.set('session:abc', 'user123');
// const value = await client.get('session:abc');
"#,
        ),
        "go" => (
            "cachee_client.go",
            r#"// Cachee Go client — connects to local daemon via RESP.
package cachee

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type Client struct {
	Addr string
}

func NewClient(addr string) *Client {
	if addr == "" {
		addr = "127.0.0.1:6380"
	}
	return &Client{Addr: addr}
}

func (c *Client) send(cmd string) (string, error) {
	conn, err := net.DialTimeout("tcp", c.Addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, "%s\r\n", cmd)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (c *Client) Set(key, value string) error {
	_, err := c.send(fmt.Sprintf("SET %s %s", key, value))
	return err
}

func (c *Client) Get(key string) (string, error) {
	resp, err := c.send(fmt.Sprintf("GET %s", key))
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(resp, "$-1") {
		return "", nil
	}
	parts := strings.Split(resp, "\r\n")
	if len(parts) > 1 {
		return parts[1], nil
	}
	return "", nil
}

func (c *Client) Del(key string) (bool, error) {
	resp, err := c.send(fmt.Sprintf("DEL %s", key))
	return strings.Contains(resp, ":1"), err
}
"#,
        ),
        _ => unreachable!(),
    };

    let file_path = dir.join(filename);
    std::fs::write(&file_path, content)?;

    println!("SDK client generated: {}", file_path.display());
    println!();
    println!("  Language : {lang}");
    println!("  File     : {filename}");
    println!("  Connects : 127.0.0.1:6380 (default)");
    println!();
    println!("  Make sure Cachee is running: cachee start");

    Ok(())
}

pub async fn data_ttl(key: &str) -> anyhow::Result<()> {
    // TTL check via RESP - would need TTL command in RESP handler
    println!("TTL for '{}': (not yet implemented in RESP handler)", key);
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.2} KiB", bytes as f64 / 1_024.0)
    } else {
        format!("{bytes} bytes")
    }
}
