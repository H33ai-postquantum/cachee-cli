//! Cachee CLI — the world's first post-quantum caching service.
//!
//! Commands:
//!   cachee init       — Initialize config and generate PQ keypair
//!   cachee start      — Start the cache daemon (RESP on port 6380)
//!   cachee stop       — Stop the running daemon
//!   cachee status     — Show daemon status, stats, and hit rate
//!   cachee attest     — Enable/disable PQ attestation (Substrate)
//!   cachee bench      — Run built-in throughput/latency benchmark
//!   cachee cluster    — Federated D-Cachee operations
//!   cachee get/set    — Direct cache operations from terminal

use clap::{Parser, Subcommand};

mod config;
mod daemon;
mod resp;
mod bench;
mod attest;

#[derive(Parser)]
#[command(
    name = "cachee",
    version,
    about = "The world's first post-quantum caching service",
    long_about = "Cachee — high-performance cache with PQ attestation.\nEvery entry carries a 58-byte Substrate receipt signed by 3 independent PQ families.\nCache poisoning is cryptographically impossible."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize Cachee — create config, generate PQ keypair
    Init {
        /// Port for RESP server
        #[arg(long, default_value = "6380")]
        port: u16,
        /// Maximum cache entries
        #[arg(long, default_value = "1000000")]
        max_keys: usize,
        /// Default TTL in seconds
        #[arg(long, default_value = "3600")]
        ttl: u32,
    },
    /// Start the Cachee daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
        /// Config file path
        #[arg(long)]
        config: Option<String>,
    },
    /// Stop the running daemon
    Stop,
    /// Show daemon status, stats, hit rate
    Status,
    /// Cache operations
    Set {
        key: String,
        value: String,
        /// TTL in seconds
        #[arg(long)]
        ttl: Option<u32>,
    },
    Get {
        key: String,
        /// Show attestation receipt
        #[arg(long)]
        receipt: bool,
    },
    Del {
        key: String,
    },
    /// PQ attestation control
    Attest {
        #[command(subcommand)]
        action: AttestAction,
    },
    /// Run built-in benchmark
    Bench {
        /// Duration in seconds
        #[arg(long, default_value = "10")]
        duration: u64,
        /// Number of concurrent workers
        #[arg(long, default_value = "8")]
        workers: usize,
    },
    /// D-Cachee federation
    Cluster {
        #[command(subcommand)]
        action: ClusterAction,
    },
}

#[derive(Subcommand)]
enum AttestAction {
    /// Enable PQ attestation on all SET operations
    Enable,
    /// Disable PQ attestation
    Disable,
    /// Show attestation status and key info
    Status,
}

#[derive(Subcommand)]
enum ClusterAction {
    /// Join a D-Cachee federation
    Join {
        /// Comma-separated peer addresses
        #[arg(long)]
        peers: String,
    },
    /// Leave the federation
    Leave,
    /// Show cluster status
    Status,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("cachee=info".parse().unwrap())
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { port, max_keys, ttl } => {
            config::init(port, max_keys, ttl).await?;
        }
        Commands::Start { foreground, config: config_path } => {
            daemon::start(foreground, config_path).await?;
        }
        Commands::Stop => {
            daemon::stop().await?;
        }
        Commands::Status => {
            daemon::status().await?;
        }
        Commands::Set { key, value, ttl } => {
            resp::set(&key, &value, ttl).await?;
        }
        Commands::Get { key, receipt } => {
            resp::get(&key, receipt).await?;
        }
        Commands::Del { key } => {
            resp::del(&key).await?;
        }
        Commands::Attest { action } => match action {
            AttestAction::Enable => attest::enable().await?,
            AttestAction::Disable => attest::disable().await?,
            AttestAction::Status => attest::status().await?,
        },
        Commands::Bench { duration, workers } => {
            bench::run(duration, workers).await?;
        }
        Commands::Cluster { action } => match action {
            ClusterAction::Join { peers } => {
                println!("Joining D-Cachee federation: {peers}");
                println!("(federation support coming in v0.2)");
            }
            ClusterAction::Leave => {
                println!("Left D-Cachee federation");
            }
            ClusterAction::Status => {
                println!("Not connected to any federation");
            }
        },
    }

    Ok(())
}
